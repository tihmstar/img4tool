#!/usr/bin/env python3
"""
usb_descriptor_check.py

List USB descriptors and test claiming / altsetting / bulk reads using PyUSB.

Usage:
  python3 usb_descriptor_check.py /dev/bus/usb/001/003
  or
  python3 usb_descriptor_check.py vid:pid

This script attempts to use libusb via PyUSB to enumerate descriptors and
also performs a small test: claim interface, set altsetting, read from bulk IN.

Note: Running this usually requires appropriate permissions (root or usb access).
"""
import sys
import os
import binascii
import usb.core
import usb.util


def find_device_by_path(path):
    # path like /dev/bus/usb/BBB/DDD
    try:
        parts = path.strip().split('/')
        bus = int(parts[-2])
        addr = int(parts[-1])
    except Exception:
        return None
    for d in usb.core.find(find_all=True):
        # pyusb exposes bus and address attributes on many backends
        try:
            if getattr(d, 'bus', None) == bus and getattr(d, 'address', None) == addr:
                return d
        except Exception:
            pass
    return None


def find_device_by_vidpid(spec):
    vid, pid = spec.split(':')
    try:
        vid = int(vid, 16) if vid.startswith('0x') or ':' not in vid else int(vid, 16)
    except Exception:
        vid = int(vid, 16)
    pid = int(pid, 16)
    return usb.core.find(idVendor=vid, idProduct=pid)


def ctrl_get_descriptor(dev, desc_type, desc_index=0, length=256, timeout=1000):
    # bmRequestType: 0x80 (device->host, standard, device)
    GET_DESCRIPTOR = 0x06
    bmRequestType = 0x80
    wValue = (desc_type << 8) | desc_index
    try:
        data = dev.ctrl_transfer(bmRequestType, GET_DESCRIPTOR, wValue, 0, length, timeout=timeout)
        return bytes(data)
    except usb.core.USBError as e:
        print(f"[ERROR] ctrl_transfer GET_DESCRIPTOR type={desc_type} failed: {e}")
        return None


def print_hexdump(label, data):
    print(f"\n{label} (len={len(data)}):")
    hexed = binascii.hexlify(data).decode('ascii')
    # print in rows
    for i in range(0, len(hexed), 32):
        print(hexed[i:i+32])


def dump_device_info(dev):
    print(f"Found device: VID=0x{dev.idVendor:04x} PID=0x{dev.idProduct:04x}")
    print(f"Device class/subclass/protocol: {dev.bDeviceClass}/{dev.bDeviceSubClass}/{dev.bDeviceProtocol}")
    # Raw device descriptor
    dev_desc = ctrl_get_descriptor(dev, 1, 0, 18)
    if dev_desc:
        print_hexdump("Raw Device Descriptor", dev_desc)

    # Iterate configurations
    for cfg in dev:
        print(f"\nConfiguration: value={cfg.bConfigurationValue} attributes=0x{cfg.bmAttributes:02x} maxpower={cfg.bMaxPower}")
        # fetch raw config descriptor first 9 bytes to find total length
        raw9 = ctrl_get_descriptor(dev, 2, 0, 9)
        total_len = None
        if raw9 and len(raw9) >= 9:
            total_len = raw9[2] | (raw9[3] << 8)
        if total_len:
            rawcfg = ctrl_get_descriptor(dev, 2, 0, total_len)
            if rawcfg:
                print_hexdump(f"Raw Config Descriptor (cfg {cfg.bConfigurationValue})", rawcfg)

        for intf in cfg:
            for alt in intf:
                print(f"\nInterface number {alt.bInterfaceNumber}")
                print(f"  Altsetting {alt.bAlternateSetting}")
                print(f"    Class/Subclass/Protocol: {alt.bInterfaceClass}/{alt.bInterfaceSubClass}/{alt.bInterfaceProtocol}")
                # endpoints
                bulk_in = None
                bulk_out = None
                for ep in alt.endpoints():
                    addr = ep.bEndpointAddress
                    ep_dir = 'IN' if usb.util.endpoint_direction(addr) == usb.util.ENDPOINT_IN else 'OUT'
                    t = ep.bmAttributes & 0x03
                    tname = {0: 'Control', 1: 'Isochronous', 2: 'Bulk', 3: 'Interrupt'}.get(t, f'Unknown({t})')
                    print(f"      Endpoint 0x{addr:02x}: {ep_dir} {tname} maxpkt={ep.wMaxPacketSize}")
                    if t == 2:
                        if usb.util.endpoint_direction(addr) == usb.util.ENDPOINT_IN:
                            bulk_in = addr
                        else:
                            bulk_out = addr
                if bulk_in or bulk_out:
                    print("    -- This altsetting contains:")
                    if bulk_in:
                        print(f"       bulk IN: 0x{bulk_in:02x}")
                    if bulk_out:
                        print(f"       bulk OUT: 0x{bulk_out:02x}")


def test_claim_and_read(dev, ifnum, altsetting=None, read_len=512, timeout=1000):
    print(f"\n-- Test: claim interface {ifnum} altsetting={altsetting} --")
    reattached = False
    try:
        if dev.is_kernel_driver_active(ifnum):
            print(f"Kernel driver active on interface {ifnum}, detaching...")
            try:
                dev.detach_kernel_driver(ifnum)
                reattached = True
            except usb.core.USBError as e:
                print(f"Failed to detach kernel driver: {e}")
        usb.util.claim_interface(dev, ifnum)
        print("Claim succeeded")
        if altsetting is not None:
            try:
                dev.set_interface_altsetting(interface=ifnum, alternate_setting=altsetting)
                print("Set altsetting succeeded")
            except usb.core.USBError as e:
                print(f"Set altsetting failed: {e}")

        # find bulk IN endpoint on this interface
        cfg = dev.get_active_configuration()
        ep_in = None
        for intf in cfg:
            if intf.bInterfaceNumber != ifnum:
                continue
            for alt in intf:
                if alt.bAlternateSetting != (altsetting if altsetting is not None else alt.bAlternateSetting):
                    continue
                for ep in alt.endpoints():
                    if (ep.bmAttributes & 0x03) == 2 and usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                        ep_in = ep.bEndpointAddress
                        break
                if ep_in:
                    break
            if ep_in:
                break

        if not ep_in:
            print("No bulk IN endpoint found for this interface/altsetting")
        else:
            print(f"Attempting to read {read_len} bytes from bulk IN 0x{ep_in:02x} (timeout={timeout}ms)")
            try:
                data = dev.read(ep_in, read_len, timeout)
                print(f"Read {len(data)} bytes:\n{bytes(data)!r}")
            except usb.core.USBError as e:
                print(f"Bulk read failed: {e}")

    except usb.core.USBError as e:
        print(f"Claim/interface test USB error: {e}")
    finally:
        try:
            usb.util.release_interface(dev, ifnum)
            print("Released interface")
        except Exception:
            pass
        # try reattach kernel driver if we detached
        if reattached:
            try:
                dev.attach_kernel_driver(ifnum)
            except Exception:
                pass


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    target = sys.argv[1]
    dev = None
    if target.startswith('/dev/bus/usb/'):
        dev = find_device_by_path(target)
    elif ':' in target:
        try:
            dev = find_device_by_vidpid(target)
        except Exception:
            dev = None
    else:
        print("Specify /dev/bus/usb/BBB/DDD or vid:pid")
        sys.exit(1)

    if dev is None:
        print(f"Device not found for '{target}'")
        sys.exit(2)

    try:
        dump_device_info(dev)

        # Ask user which interface to test; attempt to auto-select an interface containing bulk endpoints
        cfg = dev.get_active_configuration()
        candidate = None
        for intf in cfg:
            for alt in intf:
                for ep in alt.endpoints():
                    if (ep.bmAttributes & 0x03) == 2:
                        candidate = intf.bInterfaceNumber
                        break
                if candidate is not None:
                    break
            if candidate is not None:
                break

        if candidate is None:
            print("No interface with bulk endpoints found in active configuration. You can still try by specifying interface number manually.")
        else:
            print(f"Auto-selected interface {candidate} for test")
            test_claim_and_read(dev, candidate, altsetting=0)

    except usb.core.USBError as e:
        print(f"USB operation failed: {e}")


if __name__ == '__main__':
    main()
