#!/usr/bin/env python3
"""
Termux Restore Client — restored protocol over raw USB (no libusb, no usbmuxd).

Implements the full post-boot restore chain:
  usbmux (USB-level TCP multiplexing) → restored (plist protocol) → ASR (rootfs)

Usage (from Termux, after kernel has booted via restore-boot):
    termux-usb -e 'python3 scripts/restore_client.py --ipsw ~/restore_work/ipsw_extracted \
        --manifest ~/restore_work/BuildManifest.plist \
        --personalized ~/restore_work/personalized' /dev/bus/usb/001/XXX

Architecture:
    ┌─────────────┐
    │ restored     │  plist request/response over TCP port 62078
    ├─────────────┤
    │ usbmux TCP  │  mini TCP stack (SYN/ACK/FIN) over USB mux protocol
    ├─────────────┤
    │ USB bulk I/O│  USBDEVFS ioctl (raw fd from termux-usb)
    └─────────────┘

Ported from: libimobiledevice/usbmuxd (device.c) + idevicerestore (restore.c, asr.c)
"""

import sys
import os
import struct
import socket
import time
import fcntl
import ctypes
import plistlib
import hashlib
import argparse
import select
import threading
from collections import OrderedDict

# ---------------------------------------------------------------------------
# USBDEVFS ioctl definitions (matches our C usb_handler.c)
# ---------------------------------------------------------------------------
USBDEVFS_CONTROL     = 0xC0185500
USBDEVFS_BULK        = 0xC0185502
USBDEVFS_CLAIMINTERFACE = 0x8004550F
USBDEVFS_RELEASEINTERFACE = 0x80045510
USBDEVFS_SETINTERFACE = 0x80085504
USBDEVFS_CLEAR_HALT  = 0x80045515
USBDEVFS_IOCTL       = 0xC0105512
USBDEVFS_DISCONNECT  = 0x00005516

# On ARM64 Android the ioctl numbers may differ; detect at runtime
import platform
if platform.machine() in ('aarch64', 'arm64', 'armv8l'):
    # ARM64 ioctl encoding
    USBDEVFS_CONTROL     = 0xC0185500
    USBDEVFS_BULK        = 0xC0185502
    USBDEVFS_CLAIMINTERFACE = 0x8004550F
    USBDEVFS_RELEASEINTERFACE = 0x80045510
    USBDEVFS_SETINTERFACE = 0x80085504
    USBDEVFS_CLEAR_HALT  = 0x80045515

# ---------------------------------------------------------------------------
# USB bulk I/O layer (same as our C code but in Python via fcntl.ioctl)
# ---------------------------------------------------------------------------
# ctypes structs for USBDEVFS ioctl — handles ARM64/x86 alignment automatically
class usbdevfs_ctrltransfer(ctypes.Structure):
    _fields_ = [
        ('bRequestType', ctypes.c_uint8),
        ('bRequest', ctypes.c_uint8),
        ('wValue', ctypes.c_uint16),
        ('wIndex', ctypes.c_uint16),
        ('wLength', ctypes.c_uint16),
        ('timeout', ctypes.c_uint32),
        ('data', ctypes.c_void_p),
    ]

class usbdevfs_bulktransfer(ctypes.Structure):
    _fields_ = [
        ('ep', ctypes.c_uint),
        ('len', ctypes.c_uint),
        ('timeout', ctypes.c_uint),
        ('data', ctypes.c_void_p),
    ]

class usbdevfs_setinterface(ctypes.Structure):
    _fields_ = [
        ('interface', ctypes.c_uint),
        ('altsetting', ctypes.c_uint),
    ]

class usbdevfs_disconnect_ioctl(ctypes.Structure):
    _fields_ = [
        ('ifno', ctypes.c_int),
        ('ioctl_code', ctypes.c_uint),
        ('data', ctypes.c_void_p),
    ]


class USBDevice:
    """Raw USBDEVFS device handle."""

    def __init__(self, fd):
        self.fd = fd
        self.ep_in = 0x85   # bulk IN  (will be auto-detected)
        self.ep_out = 0x04  # bulk OUT (will be auto-detected)

    def claim_interface(self, iface):
        """Claim a USB interface."""
        try:
            # Disconnect kernel driver first
            disc = usbdevfs_disconnect_ioctl()
            disc.ifno = iface
            disc.ioctl_code = USBDEVFS_DISCONNECT
            disc.data = 0
            try:
                fcntl.ioctl(self.fd, USBDEVFS_IOCTL, disc)
            except OSError:
                pass
            # Claim
            iface_buf = ctypes.c_uint(iface)
            fcntl.ioctl(self.fd, USBDEVFS_CLAIMINTERFACE, iface_buf)
            print(f"[USB] Claimed interface {iface}")
            return True
        except OSError as e:
            print(f"[USB] Cannot claim interface {iface}: {e}")
            return False

    def set_interface(self, iface, alt):
        """Set interface alt setting."""
        si = usbdevfs_setinterface()
        si.interface = iface
        si.altsetting = alt
        try:
            fcntl.ioctl(self.fd, USBDEVFS_SETINTERFACE, si)
            return True
        except OSError as e:
            print(f"[USB] Cannot set iface {iface} alt {alt}: {e}")
            return False

    def bulk_write(self, data, timeout=5000):
        """Send data via bulk OUT endpoint."""
        c_data = ctypes.create_string_buffer(bytes(data))
        bulk = usbdevfs_bulktransfer()
        bulk.ep = self.ep_out
        bulk.len = len(data)
        bulk.timeout = timeout
        bulk.data = ctypes.addressof(c_data)
        try:
            print(f"[USB-WRITE] len={len(data)}")
            print("[USB-WRITE] " + bytes(data[:64]).hex())
            fcntl.ioctl(self.fd, USBDEVFS_BULK, bulk)
            return len(data)
        except OSError as e:
            print(f"[USB] Bulk write failed: {e}")
            return -1

    def bulk_read(self, size=65536, timeout=5000):
        """Receive data via bulk IN endpoint."""
        c_data = ctypes.create_string_buffer(size)
        bulk = usbdevfs_bulktransfer()
        bulk.ep = self.ep_in
        bulk.len = size
        bulk.timeout = timeout
        bulk.data = ctypes.addressof(c_data)
        try:
            # USBDEVFS_BULK returns the number of bytes actually transferred.
            n = fcntl.ioctl(self.fd, USBDEVFS_BULK, bulk)
            if n <= 0:
                return b''
            return bytes(c_data.raw[:n])
        except OSError as e:
            if e.errno == 110:  # ETIMEDOUT
                return b''
            print(f"[USB] Bulk read failed: {e}")
            return None

    def ctrl_transfer(self, bmRequestType, bRequest, wValue, wIndex,
                      data=None, wLength=0, timeout=5000):
        """Control transfer."""
        buf_len = max(len(data) if data else 0, wLength, 1)
        c_data = ctypes.create_string_buffer(buf_len)
        if data:
            ctypes.memmove(c_data, data, len(data))
        ctrl = usbdevfs_ctrltransfer()
        ctrl.bRequestType = bmRequestType
        ctrl.bRequest = bRequest
        ctrl.wValue = wValue
        ctrl.wIndex = wIndex
        ctrl.wLength = buf_len
        ctrl.timeout = timeout
        ctrl.data = ctypes.addressof(c_data)
        try:
            fcntl.ioctl(self.fd, USBDEVFS_CONTROL, ctrl)
            return bytes(c_data.raw[:wLength]) if (bmRequestType & 0x80) else buf_len
        except OSError as e:
            return None

    def _read_config_descriptor(self):
        """Read the full configuration descriptor (following wTotalLength)."""
        head = self.ctrl_transfer(0x80, 0x06, 0x0200, 0, wLength=9)
        if not head or len(head) < 4:
            return None
        total_len = head[2] | (head[3] << 8)
        if total_len < 9:
            total_len = 255
        desc = self.ctrl_transfer(0x80, 0x06, 0x0200, 0, wLength=total_len)
        return desc

    def find_mux_interface(self):
        """Parse the configuration descriptor and locate the usbmux interface.

        The usbmux/restore interface is a vendor-specific interface
        (bInterfaceClass=0xFF, bInterfaceSubClass=0xFE) with one bulk IN and
        one bulk OUT endpoint. Returns (iface_no, alt_setting) or None.
        Also sets self.ep_in / self.ep_out."""
        desc = self._read_config_descriptor()
        if not desc or len(desc) < 4:
            print("[USB] Could not read configuration descriptor")
            return None
        candidates = []
        cur = None
        i = 0
        while i < len(desc) - 1:
            blen = desc[i]
            btype = desc[i+1]
            if blen == 0:
                break
            if btype == 4 and blen >= 9:  # interface descriptor
                cur = {
                    'iface': desc[i+2], 'alt': desc[i+3],
                    'cls': desc[i+5], 'sub': desc[i+6], 'proto': desc[i+7],
                    'ep_in': None, 'ep_out': None,
                }
                candidates.append(cur)
            elif btype == 5 and blen >= 7 and cur is not None:  # endpoint
                ep_addr = desc[i+2]
                ep_attr = desc[i+3]
                if (ep_attr & 0x03) == 0x02:  # bulk
                    if ep_addr & 0x80:
                        cur['ep_in'] = ep_addr
                    else:
                        cur['ep_out'] = ep_addr
            i += blen
        for c in candidates:
            print(f"[USB]   iface {c['iface']} alt {c['alt']} "
                  f"class=0x{c['cls']:02x} sub=0x{c['sub']:02x} proto=0x{c['proto']:02x} "
                  f"IN={c['ep_in']} OUT={c['ep_out']}")
        # Prefer the vendor-specific mux interface (0xFF / 0xFE).
        chosen = None
        for c in candidates:
            if c['cls'] == 0xFF and c['sub'] == 0xFE and c['ep_in'] and c['ep_out']:
                chosen = c
                break
        if not chosen:
            for c in candidates:
                if c['ep_in'] and c['ep_out']:
                    chosen = c
                    break
        if not chosen:
            print("[USB] No interface with bulk IN+OUT endpoints found")
            return None
        self.ep_in = chosen['ep_in']
        self.ep_out = chosen['ep_out']
        print(f"[USB] Selected mux interface {chosen['iface']} alt {chosen['alt']} "
              f"(class=0x{chosen['cls']:02x} sub=0x{chosen['sub']:02x}) "
              f"IN=0x{self.ep_in:02x} OUT=0x{self.ep_out:02x}")
        return (chosen['iface'], chosen['alt'])


# ---------------------------------------------------------------------------
# usbmux USB-level protocol (ported from usbmuxd/device.c)
# ---------------------------------------------------------------------------
MUX_PROTO_VERSION = 0
MUX_PROTO_SETUP   = 2
MUX_PROTO_TCP     = 6  # IPPROTO_TCP

TH_SYN = 0x02
TH_ACK = 0x10
TH_RST = 0x04
TH_FIN = 0x01

USB_MTU = 65536
DEV_MRU = 65536

class MuxHeader:
    """USB mux header (version 2, 16 bytes)."""
    SIZE = 16
    MAGIC = 0xfeedface

    def __init__(self, protocol=0, length=0, tx_seq=0, rx_seq=0):
        self.protocol = protocol
        self.length = length
        self.magic = self.MAGIC
        self.tx_seq = tx_seq
        self.rx_seq = rx_seq

    def pack(self):
        return struct.pack('>IIIHH',
                           self.protocol, self.length, self.magic,
                           self.tx_seq, self.rx_seq)

    @classmethod
    def unpack(cls, data):
        if len(data) < cls.SIZE:
            return None
        proto, length, magic, tx_seq, rx_seq = struct.unpack('>IIIHH', data[:cls.SIZE])
        h = cls(proto, length, tx_seq, rx_seq)
        h.magic = magic
        return h


class TCPHeader:
    """TCP-like header for usbmux (20 bytes)."""
    SIZE = 20

    def __init__(self, sport=0, dport=0, seq=0, ack=0, flags=0, window=0):
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.offset = 5  # 20 bytes / 4
        self.window = window
        self.checksum = 0
        self.urgent = 0

    def pack(self):
        off_flags = (self.offset << 4)
        return struct.pack('>HHIIBBHHH',
                           self.sport, self.dport,
                           self.seq, self.ack,
                           off_flags, self.flags,
                           self.window, self.checksum, self.urgent)

    @classmethod
    def unpack(cls, data):
        if len(data) < cls.SIZE:
            return None
        sport, dport, seq, ack, off, flags, window, check, urgent = \
            struct.unpack('>HHIIBBHHH', data[:cls.SIZE])
        h = cls(sport, dport, seq, ack, flags, window >> 8 if window else 0)
        h.offset = off >> 4
        h.window = window
        return h


class MuxConnection:
    """A single TCP-over-USB connection."""

    def __init__(self, dev, sport, dport):
        self.dev = dev
        self.sport = sport
        self.dport = dport
        self.state = 'CONNECTING'
        # usbmux pseudo-TCP accounting (see usbmuxd/device.c):
        #   tx_seq = 1 + bytes we have sent
        #   tx_ack = 1 + bytes from the device we have consumed
        self.tx_seq = 0
        self.tx_ack = 0
        self.tx_win = 131072
        self.rx_seq = 0
        self.rx_ack = 0
        self.rx_win = 0
        self.inbuf = bytearray()

    def send_tcp(self, flags, data=b''):
        th = TCPHeader(self.sport, self.dport, self.tx_seq, self.tx_ack,
                       flags, self.tx_win >> 8)
        self.dev.send_mux_packet(MUX_PROTO_TCP, th.pack(), data)
        if data:
            self.tx_seq += len(data)

    def handle_tcp(self, th, payload):
        """Process an incoming TCP packet (mirrors device_tcp_input)."""
        self.rx_seq = th.seq
        self.rx_ack = th.ack
        self.rx_win = th.window << 8

        if self.state == 'CONNECTING':
            if th.flags != (TH_SYN | TH_ACK):
                if th.flags & TH_RST:
                    self.state = 'REFUSED'
                else:
                    self.state = 'DEAD'
                print(f"[MUX] Connection refused on port {self.dport} "
                      f"(flags=0x{th.flags:02x})")
                return
            # SYN consumes one sequence number on each side.
            self.tx_seq += 1
            self.tx_ack += 1
            self.send_tcp(TH_ACK)
            self.state = 'CONNECTED'
            print(f"[MUX] Connection established to port {self.dport}")
            return

        if self.state == 'CONNECTED':
            if th.flags & TH_RST:
                print(f"[MUX] Connection reset by device on port {self.dport}")
                self.state = 'DEAD'
                return
            if payload:
                self.inbuf.extend(payload)
                # We consume data immediately, so advance the ack and notify.
                self.tx_ack += len(payload)
                self.send_tcp(TH_ACK)

    def write(self, data):
        """Send data over the connection."""
        if self.state != 'CONNECTED':
            return -1
        # Fragment into chunks that fit in USB MTU
        max_payload = USB_MTU - MuxHeader.SIZE - TCPHeader.SIZE
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + max_payload]
            self.send_tcp(TH_ACK, chunk)
            offset += len(chunk)
        return len(data)

    def read(self, size=None, timeout=5.0):
        """Read data from the connection buffer."""
        start = time.time()
        while len(self.inbuf) == 0:
            if time.time() - start > timeout:
                return b''
            self.dev.process_packets(timeout=0.1)
        if size is None:
            data = bytes(self.inbuf)
            self.inbuf.clear()
        else:
            data = bytes(self.inbuf[:size])
            del self.inbuf[:size]
        return data

CONN_OUTBUF_SIZE = 65536

class MuxDevice:
    """usbmux device — manages USB I/O and TCP connections."""

    def __init__(self, usb_dev):
        self.usb = usb_dev
        self.version = 0  # negotiated during init_mux (starts at 0)
        self.tx_seq = 0
        self.rx_seq = 0xFFFF
        self.connections = {}
        self.next_sport = 1
        self.active = False
        self.recv_buf = bytearray()
        self.iface = None

    def init_mux(self):
        """Initialize mux: claim the mux interface, perform version handshake.

        Matches usbmuxd/device.c: the initial version packet is sent with
        MUX_PROTO_VERSION and an 8-byte mux header (because version is still 0).
        The device replies with its version; if >= 2 we then send a
        MUX_PROTO_SETUP packet carrying a single 0x07 byte to activate it."""
        self.version = 0
        self.tx_seq = 0
        self.rx_seq = 0xFFFF

        info = self.usb.find_mux_interface()
        if info is None:
            print("[MUX] ERROR: no usbmux interface found in config descriptor")
            return False
        iface, alt = info
        self.iface = iface

        if not self.usb.claim_interface(iface):
            print(f"[MUX] ERROR: cannot claim mux interface {iface}")
            return False
        if alt:
            self.usb.set_interface(iface, alt)

        # version_header: major=2, minor=0, padding=0 (big-endian)
        vh = struct.pack('>III', 2, 0, 0)
        self.send_mux_packet(MUX_PROTO_VERSION, vh, b'')

        print("[MUX] Sent version packet, waiting for response...")
        for _ in range(50):  # ~5 seconds
            self.process_packets(timeout=0.1)
            if self.active:
                print(f"[MUX] Device active (mux protocol v{self.version})")
                return True

        print("[MUX] ERROR: No version response from device")
        return False

    def send_mux_packet(self, proto, header, data=b''):
        """Send a mux packet over USB.

        Header size depends on the negotiated version: 8 bytes (protocol +
        length only) while version < 2, 16 bytes (with magic/tx_seq/rx_seq)
        once version >= 2."""
        if self.version >= 2:
            mux_hdr_size = 16
            total = mux_hdr_size + len(header) + len(data)
            if proto == MUX_PROTO_SETUP:
                self.tx_seq = 0
                self.rx_seq = 0xFFFF
            mhdr = struct.pack('>IIIHH', proto, total, MuxHeader.MAGIC,
                               self.tx_seq & 0xFFFF, self.rx_seq & 0xFFFF)
            self.tx_seq += 1
        else:
            mux_hdr_size = 8
            total = mux_hdr_size + len(header) + len(data)
            mhdr = struct.pack('>II', proto, total)

        packet = mhdr + header + data
        ret = self.usb.bulk_write(packet)
        if ret < 0:
            print(f"[MUX] USB send failed")
            return -1
        return total

    def process_packets(self, timeout=0.1):
        """Read and process incoming USB packets."""
        data = self.usb.bulk_read(USB_MTU, int(timeout * 1000))
        print(f"[MUX-DEBUG] bulk_read returned: {data!r}")
        if data:
            print(f"[MUX-RAW] received {len(data)} bytes")
            print("[MUX-RAW] " + bytes(data[:64]).hex())
            self.recv_buf.extend(data)

        while len(self.recv_buf) >= 8:
            proto, length = struct.unpack('>II', self.recv_buf[:8])
            if length < 8 or length > USB_MTU:
                print(f"[MUX] Bad packet length {length}; resyncing (buf={len(self.recv_buf)})")
                self.recv_buf.clear()
                return
            if length > len(self.recv_buf):
                break  # incomplete packet

            pkt = bytes(self.recv_buf[:length])
            del self.recv_buf[:length]

            if self.version >= 2:
                hdr_size = 16
                if length >= 16:
                    tx_seq, rx_seq = struct.unpack('>HH', pkt[12:16])
                    self.rx_seq = tx_seq
            else:
                hdr_size = 8
            payload = pkt[hdr_size:]

            if proto == MUX_PROTO_VERSION:
                if len(payload) >= 8:
                    major, minor = struct.unpack('>II', payload[:8])
                    print(f"[MUX] Device version: {major}.{minor}")
                    self.version = major if major <= 2 else 2
                    if self.version >= 2:
                        # Activate the mux (control payload type 7).
                        self.send_mux_packet(MUX_PROTO_SETUP, b'', b'\x07')
                    self.active = True

            elif proto == MUX_PROTO_TCP:
                if len(payload) >= TCPHeader.SIZE:
                    th = TCPHeader.unpack(payload)
                    thoff = th.offset * 4 if th.offset >= 5 else TCPHeader.SIZE
                    tcp_payload = payload[thoff:]
                    conn = self.connections.get(th.dport)
                    if conn:
                        conn.handle_tcp(th, tcp_payload)

    def connect(self, port):
        """Open a TCP connection to a port on the device."""
        sport = self.next_sport
        self.next_sport += 1

        conn = MuxConnection(self, sport, port)
        self.connections[sport] = conn

        # Send SYN
        conn.send_tcp(TH_SYN)
        print(f"[MUX] Connecting to port {port}...")

        # Wait for SYN+ACK
        for _ in range(100):  # 10 seconds
            self.process_packets(timeout=0.1)
            if conn.state == 'CONNECTED':
                return conn
            if conn.state in ('REFUSED', 'DEAD'):
                print(f"[MUX] Connection refused to port {port}")
                return None

        print(f"[MUX] Connection timeout to port {port}")
        return None


# ---------------------------------------------------------------------------
# restored protocol (ported from idevicerestore/restore.c)
# ---------------------------------------------------------------------------
RESTORED_PORT = 62078  # lockdownd/restored port

# Restore message types (from idevicerestore)
CREATE_PARTITION_MAP     = 11
CREATE_FILESYSTEM        = 12
RESTORE_IMAGE            = 13
VERIFY_RESTORE           = 14
CHECK_FILESYSTEMS        = 15
MOUNT_FILESYSTEMS        = 16
FIXUP_VAR               = 17
FLASH_FIRMWARE           = 18
UPDATE_BASEBAND          = 19
SET_BOOT_STAGE           = 20
REBOOT_DEVICE            = 21
SHUTDOWN_DEVICE          = 22
TURN_ON_ACCESSORY_POWER  = 23
CLEAR_BOOTARGS           = 24
MODIFY_BOOTARGS          = 25
INSTALL_ROOT             = 26
INSTALL_KERNELCACHE      = 27
WAIT_FOR_NAND            = 28
UNMOUNT_FILESYSTEMS      = 29
SET_DATETIME             = 30
EXEC_IBOOT               = 31
FINALIZE_NAND_EPOCH_UPDATE = 32
CHECK_IBOOT_STAGE        = 33
SEND_APPLE_LOGO          = 34
CREATE_FACTORY_RESTORE_DATA = 35
LOAD_SEP_OS              = 36
SEND_RESTORE_LOCAL_POLICY = 37


class RestoredClient:
    """Communicate with the restored daemon on the device."""

    def __init__(self, mux_conn):
        self.conn = mux_conn
        self.tag = 0

    def send_plist(self, plist_dict):
        """Send a plist message to restored."""
        data = plistlib.dumps(plist_dict, fmt=plistlib.FMT_XML)
        # Prepend 4-byte big-endian length
        header = struct.pack('>I', len(data))
        self.conn.write(header + data)

    def recv_plist(self, timeout=30.0):
        """Receive a plist message from restored."""
        # Read 4-byte length header (may be fragmented across packets)
        header = b''
        while len(header) < 4:
            chunk = self.conn.read(4 - len(header), timeout=timeout)
            if not chunk:
                break
            header += chunk
        if len(header) < 4:
            return None
        length = struct.unpack('>I', header)[0]
        if length == 0 or length > 10 * 1024 * 1024:
            print(f"[RESTORED] Invalid plist length: {length}")
            return None

        # Read plist body
        body = b''
        remaining = length
        while remaining > 0:
            chunk = self.conn.read(remaining, timeout=timeout)
            if not chunk:
                break
            body += chunk
            remaining -= len(chunk)

        try:
            return plistlib.loads(body)
        except Exception as e:
            print(f"[RESTORED] Failed to parse plist: {e}")
            print(f"[RESTORED] Raw data ({len(body)} bytes): {body[:200]}")
            return None

    def query_type(self):
        """Send QueryType to identify the device mode."""
        self.send_plist({
            'Label': 'idevicerestore',
            'Request': 'QueryType',
        })
        resp = self.recv_plist()
        if resp:
            print(f"[RESTORED] QueryType response: {resp.get('Type', 'unknown')}")
        return resp

    def query_value(self, key=None):
        """Query a value from restored."""
        req = {
            'Label': 'idevicerestore',
            'Request': 'QueryValue',
        }
        if key:
            req['QueryKey'] = key
        self.send_plist(req)
        return self.recv_plist()

    def start_restore(self, opts):
        """Send StartRestore to begin the restore process."""
        self.send_plist({
            'Label': 'idevicerestore',
            'Request': 'StartRestore',
            'RestoreProtocolVersion': 14,
            'RestoreOptions': opts,
        })
        return self.recv_plist()

    def handle_data_request(self, msg, ipsw_dir, manifest, personalized_dir):
        """Handle a DataRequestMsg from restored."""
        data_type = msg.get('DataType', '')
        print(f"\n[RESTORED] DataRequest: {data_type}")

        if data_type == 'SystemImageData':
            return self.handle_system_image(msg, ipsw_dir)
        elif data_type == 'KernelCache':
            return self.send_component_file(personalized_dir, 'kernelcache.personalized.img4')
        elif data_type == 'DeviceTree':
            return self.send_component_file(personalized_dir, 'devicetree.personalized.img4')
        elif data_type == 'NORData':
            return self.handle_nor_data(msg, ipsw_dir, manifest, personalized_dir)
        elif data_type == 'BasebandData':
            return self.handle_baseband_data(msg, ipsw_dir, manifest, personalized_dir)
        elif data_type == 'FDRData':
            print("[RESTORED] FDR not implemented yet — skipping")
            return True
        elif data_type == 'RecoveryOSLocalPolicy':
            print("[RESTORED] RecoveryOSLocalPolicy — sending empty")
            self.send_plist({'DataType': data_type})
            return True
        else:
            print(f"[RESTORED] Unknown DataType: {data_type}")
            return True

    def send_component_file(self, directory, filename):
        """Send a personalized component file."""
        path = os.path.join(directory, filename)
        if not os.path.exists(path):
            print(f"[RESTORED] Component not found: {path}")
            return False
        data = open(path, 'rb').read()
        print(f"[RESTORED] Sending {filename} ({len(data)} bytes)")
        self.send_plist({
            'DataType': 'ComponentData',
            'ComponentData': data,
        })
        return True

    def handle_system_image(self, msg, ipsw_dir):
        """Handle SystemImageData request — stream rootfs via ASR."""
        print("[RESTORED] SystemImageData requested — starting ASR")
        # Find the rootfs DMG in the IPSW
        rootfs_path = None
        for f in os.listdir(ipsw_dir):
            if f.endswith('.dmg') and 'trustcache' not in f.lower():
                candidate = os.path.join(ipsw_dir, f)
                size = os.path.getsize(candidate)
                if size > 1_000_000_000:  # > 1GB = likely rootfs
                    rootfs_path = candidate
                    break

        if not rootfs_path:
            print("[RESTORED] ERROR: Could not find rootfs DMG in IPSW")
            return False

        print(f"[RESTORED] Rootfs: {rootfs_path} ({os.path.getsize(rootfs_path)} bytes)")

        # ASR needs its own connection on a different port
        # The port is typically provided in the msg
        asr_port = msg.get('DataPort', 12345)
        print(f"[RESTORED] ASR port: {asr_port}")

        # Connect to ASR port
        asr_conn = self.conn.dev.connect(asr_port)
        if not asr_conn:
            print("[RESTORED] ERROR: Could not connect to ASR port")
            return False

        asr = ASRClient(asr_conn)
        return asr.send_image(rootfs_path)

    def handle_nor_data(self, msg, ipsw_dir, manifest, personalized_dir):
        """Handle NORData request — send firmware components."""
        print("[RESTORED] NORData — sending firmware components")
        # NOR data typically includes all the firmware components
        # that were loaded by iBoot
        nor_data = {}

        # Scan personalized dir for firmware files
        for f in os.listdir(personalized_dir):
            if f.startswith('firmware_') and f.endswith('.personalized.img4'):
                data = open(os.path.join(personalized_dir, f), 'rb').read()
                name = f.replace('.personalized.img4', '').replace('firmware_', '')
                nor_data[name] = data

        self.send_plist({
            'DataType': 'NORData',
            'NORData': nor_data,
        })
        return True

    def handle_baseband_data(self, msg, ipsw_dir, manifest, personalized_dir):
        """Handle BasebandData request."""
        print("[RESTORED] BasebandData — looking for baseband firmware")
        # Find baseband in IPSW
        bb_path = None
        for f in os.listdir(ipsw_dir):
            if 'baseband' in f.lower() or f.endswith('.bbfw'):
                bb_path = os.path.join(ipsw_dir, f)
                break

        if bb_path and os.path.exists(bb_path):
            data = open(bb_path, 'rb').read()
            print(f"[RESTORED] Sending baseband ({len(data)} bytes)")
            self.send_plist({
                'DataType': 'BasebandData',
                'BasebandData': data,
            })
        else:
            print("[RESTORED] Baseband not found — sending empty response")
            self.send_plist({'DataType': 'BasebandData'})
        return True

    def restore_loop(self, ipsw_dir, manifest, personalized_dir):
        """Main restore loop — handle all messages from restored."""
        print("\n=== Starting Restore Loop ===")
        while True:
            msg = self.recv_plist(timeout=60)
            if msg is None:
                print("[RESTORED] No message received — timeout or disconnect")
                break

            msg_type = msg.get('MsgType', '')
            progress = msg.get('Progress', None)

            if progress is not None:
                pct = progress
                op = msg.get('Operation', 'Unknown')
                print(f"[PROGRESS] {op}: {pct}%")
                continue

            if 'DataType' in msg:
                self.handle_data_request(msg, ipsw_dir, manifest, personalized_dir)
                continue

            if msg_type == 'ProgressMsg':
                op = msg.get('Operation', 'Unknown')
                pct = msg.get('Progress', 0)
                print(f"[PROGRESS] {op}: {pct}%")

            elif msg_type == 'StatusMsg':
                status = msg.get('Status', 0)
                print(f"[STATUS] Status: {status}")
                if status == 0:
                    print("[STATUS] === RESTORE COMPLETE ===")
                    return True

            elif msg_type == 'CheckpointMsg':
                print(f"[CHECKPOINT] {msg}")

            elif msg_type == 'BBUpdateStatusMsg':
                print(f"[BASEBAND] {msg}")

            elif msg_type == 'DataRequestMsg':
                self.handle_data_request(msg, ipsw_dir, manifest, personalized_dir)

            else:
                print(f"[RESTORED] Unknown message: {msg}")

        return False


# ---------------------------------------------------------------------------
# ASR (Apple Software Restore) protocol
# ---------------------------------------------------------------------------
class ASRClient:
    """ASR client for streaming rootfs images."""

    def __init__(self, conn):
        self.conn = conn

    def recv_plist(self, timeout=30):
        data = self.conn.read(timeout=timeout)
        if not data:
            return None
        try:
            return plistlib.loads(data)
        except:
            return None

    def send_plist(self, d):
        data = plistlib.dumps(d, fmt=plistlib.FMT_XML)
        self.conn.write(data)

    def send_image(self, image_path):
        """Stream a rootfs image via ASR protocol."""
        file_size = os.path.getsize(image_path)
        print(f"[ASR] Sending image: {image_path} ({file_size} bytes)")

        # Wait for ASR OOB data request
        msg = self.recv_plist()
        if msg:
            print(f"[ASR] Initial message: {msg}")

        # Send image info
        checksum = b'\x00' * 20  # SHA1 placeholder
        self.send_plist({
            'Command': 'OOBData',
            'OOB Data': self._get_oob_data(image_path),
        })

        # Wait for ASR to request payload
        msg = self.recv_plist()
        if msg:
            print(f"[ASR] Response: {msg}")

        # Stream the image in chunks
        CHUNK_SIZE = 8 * 1024 * 1024  # 8MB chunks
        with open(image_path, 'rb') as f:
            sent = 0
            while sent < file_size:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                self.conn.write(chunk)
                sent += len(chunk)
                pct = int(100 * sent / file_size)
                print(f"\r[ASR] Sent {sent}/{file_size} ({pct}%)", end='', flush=True)

        print(f"\n[ASR] Image sent: {file_size} bytes")
        return True

    def _get_oob_data(self, image_path):
        """Generate OOB data for ASR handshake."""
        file_size = os.path.getsize(image_path)
        # Read first 64KB for header info
        with open(image_path, 'rb') as f:
            header = f.read(65536)
        return header


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description='Termux Restore Client')
    parser.add_argument('--ipsw', required=True, help='Path to extracted IPSW directory')
    parser.add_argument('--manifest', required=True, help='Path to BuildManifest.plist')
    parser.add_argument('--personalized', required=True, help='Path to personalized directory')
    parser.add_argument('--fd', type=int, default=None, help='USB fd (auto-detected if not set)')
    args = parser.parse_args()

    # Get USB fd — from termux-usb or command line
    fd = args.fd
    if fd is None:
        # Try environment variable (set by termux-usb wrapper)
        fd_str = os.environ.get('TERMUX_USB_FD')
        if fd_str:
            fd = int(fd_str)
        else:
            # Try fd 7 (common termux-usb default)
            fd = 7

    print(f"[MAIN] USB fd: {fd}")
    print(f"[MAIN] IPSW dir: {args.ipsw}")
    print(f"[MAIN] Personalized dir: {args.personalized}")

    # Initialize USB device
    usb = USBDevice(fd)

    # Initialize usbmux
    mux = MuxDevice(usb)
    if not mux.init_mux():
        print("[MAIN] ERROR: Failed to initialize usbmux")
        return 1

    # Connect to restored (port 62078)
    conn = mux.connect(RESTORED_PORT)
    if not conn:
        print("[MAIN] ERROR: Failed to connect to restored")
        return 1

    # Initialize restored client
    restored = RestoredClient(conn)

    # Query device type
    resp = restored.query_type()
    if resp and resp.get('Type') == 'com.apple.mobile.restored':
        print("[MAIN] Device is in restore mode!")
    else:
        print(f"[MAIN] Unexpected device type: {resp}")

    # Load manifest
    manifest = plistlib.load(open(os.path.expanduser(args.manifest), 'rb'))

    # Start restore
    restore_opts = {
        'AuthInstallEnableSso': False,
        'AutoBootDelay': 0,
        'BootImageType': 'UserOrInternal',
        'CreateFilesystemPartitions': True,
        'DFUFileType': 'RELEASE',
        'DataImage': False,
        'FlashNOR': True,
        'FormatForAPFS': True,
        'FormatForLwVM': False,
        'InstallDiags': False,
        'InstallRecoveryOS': False,
        'IsRecoveryOS': False,
        'KernelCacheType': 'Release',
        'NORImageType': 'production',
        'PersonalizedDuringPreflight': True,
        'RootToInstall': False,
        'ShouldRestoreSystemImage': True,
        'SystemImageType': 'User',
        'UpdateBaseband': True,
    }

    resp = restored.start_restore(restore_opts)
    if resp:
        print(f"[MAIN] StartRestore response: {resp}")

    # Run restore loop
    success = restored.restore_loop(
        os.path.expanduser(args.ipsw),
        manifest,
        os.path.expanduser(args.personalized),
    )

    if success:
        print("\n=== RESTORE COMPLETE ===")
        return 0
    else:
        print("\n=== RESTORE FAILED ===")
        return 1


if __name__ == '__main__':
    sys.exit(main())
