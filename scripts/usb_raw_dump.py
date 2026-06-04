#!/usr/bin/env python3
"""
usb_raw_dump.py

Read raw bytes from a bulk IN USB endpoint and print diagnostic data useful for usbmux debugging.

Usage:
  python3 usb_raw_dump.py vid:pid --iface 1 --alt 1 --ep 0x81

This script prints:
  - received byte count
  - raw hex dump of the first 128 bytes
  - first 16 bytes separately
  - interpreted 32-bit length at the configured offset as LE and BE
  - offset where the length field is read

Requires PyUSB and a USB backend (libusb) with device access.
"""

import argparse
import binascii
import sys

try:
    import usb.core
    import usb.util
except ImportError:
    print("ERROR: PyUSB is required. Install with: python3 -m pip install pyusb")
    sys.exit(1)


def parse_vidpid(text):
    if ':' not in text:
        raise argparse.ArgumentTypeError("Expected vid:pid")
    vid, pid = text.split(':', 1)
    try:
        return int(vid, 16), int(pid, 16)
    except ValueError:
        raise argparse.ArgumentTypeError("VID and PID must be hex")


def find_device(vid, pid):
    return usb.core.find(idVendor=vid, idProduct=pid)


def print_hexdump(label, data, width=16):
    print(f"{label} (len={len(data)})")
    hexed = binascii.hexlify(data).decode('ascii')
    for i in range(0, len(hexed), width * 2):
        print(hexed[i:i + width * 2])


def main():
    parser = argparse.ArgumentParser(description="Dump raw bytes from a USB bulk IN endpoint.")
    parser.add_argument('device', type=parse_vidpid, help='Device as vid:pid, e.g. 05ac:1281')
    parser.add_argument('--iface', type=int, default=1, help='Interface number')
    parser.add_argument('--alt', type=int, default=1, help='Alternate setting')
    parser.add_argument('--ep', type=lambda x: int(x, 0), default=0x81, help='Bulk IN endpoint address')
    parser.add_argument('--read', type=int, default=512, help='Number of bytes to read')
    parser.add_argument('--timeout', type=int, default=3000, help='Read timeout in ms')
    parser.add_argument('--len-offset', type=int, default=0, help='Offset of the length field to inspect')
    parser.add_argument('--dump', type=int, default=128, help='Number of bytes to show in raw dump')
    args = parser.parse_args()

    vid, pid = args.device
    dev = find_device(vid, pid)
    if dev is None:
        print(f"Device {vid:04x}:{pid:04x} not found")
        sys.exit(2)

    print(f"Found device VID=0x{vid:04x} PID=0x{pid:04x}")
    if hasattr(dev, 'is_kernel_driver_active') and dev.is_kernel_driver_active(args.iface):
        print(f"Detaching kernel driver from interface {args.iface}")
        dev.detach_kernel_driver(args.iface)

    usb.util.claim_interface(dev, args.iface)
    print(f"Claimed interface {args.iface}")

    try:
        dev.set_interface_altsetting(interface=args.iface, alternate_setting=args.alt)
        print(f"Set alternate setting {args.alt}")
    except usb.core.USBError as e:
        print(f"Warning: set_interface_altsetting failed: {e}")

    print(f"Reading {args.read} bytes from endpoint 0x{args.ep:02x} (timeout={args.timeout} ms)")
    try:
        data = bytes(dev.read(args.ep, args.read, timeout=args.timeout))
    except usb.core.USBError as e:
        print(f"Read failed: {e}")
        usb.util.release_interface(dev, args.iface)
        sys.exit(3)

    print(f"Received {len(data)} bytes")
    print_hexdump("Raw hex dump", data[:args.dump])
    first16 = data[:16]
    print("\nFirst 16 bytes:")
    print(' '.join(f'{b:02x}' for b in first16))

    if len(data) >= args.len_offset + 4:
        length_bytes = data[args.len_offset:args.len_offset + 4]
        length_le = int.from_bytes(length_bytes, 'little')
        length_be = int.from_bytes(length_bytes, 'big')
        print(f"\nLength field at offset {args.len_offset}: {length_bytes.hex()}")
        print(f"  little-endian -> {length_le} (0x{length_le:08x})")
        print(f"  big-endian    -> {length_be} (0x{length_be:08x})")
        print(f"  interpreted as ASCII: {length_bytes.decode('ascii', errors='replace')}")
    else:
        print(f"\nNot enough bytes to inspect 4-byte length at offset {args.len_offset}")

    usb.util.release_interface(dev, args.iface)
    print("Released interface")


if __name__ == '__main__':
    main()
