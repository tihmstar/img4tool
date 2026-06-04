#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <limits.h>
#include <linux/usbdevice_fs.h>

static void hexdump(const unsigned char *p, int len) {
    for (int i = 0; i < len; i += 16) {
        printf("%04x: ", i);
        for (int j = 0; j < 16 && i + j < len; ++j)
            printf("%02x ", p[i + j]);
        printf("\n");
    }
}

static const char *usb_endpoint_type(unsigned char bmAttributes) {
    unsigned int t = bmAttributes & 0x03;
    switch (t) {
        case 0: return "Control";
        case 1: return "Isochronous";
        case 2: return "Bulk";
        case 3: return "Interrupt";
        default: return "Unknown";
    }
}

static int ctrl_get_descriptor(int fd, unsigned char desc_type, unsigned char desc_index, unsigned char *buf, int len) {
    struct usbdevfs_ctrltransfer ctrl;
    memset(&ctrl, 0, sizeof(ctrl));
    ctrl.bRequestType = 0x80; /* device-to-host, standard, device */
    ctrl.bRequest = 0x06; /* GET_DESCRIPTOR */
    ctrl.wValue = (desc_type << 8) | desc_index;
    ctrl.wIndex = 0;
    ctrl.wLength = len;
    ctrl.timeout = 1000;
    ctrl.data = buf;

    int r = ioctl(fd, USBDEVFS_CONTROL, &ctrl);
    if (r < 0) {
        fprintf(stderr, "USBDEVFS_CONTROL failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    return r;
}

static int is_number_string(const char *s) {
    if (!s || !*s) return 0;
    for (const char *p = s; *p; ++p) {
        if (*p < '0' || *p > '9') return 0;
    }
    return 1;
}

static int parse_fd_string(const char *s, int *out_fd) {
    char *endptr = NULL;
    long value = strtol(s, &endptr, 10);
    if (endptr == NULL || *endptr != '\0' || value < 0 || value > INT_MAX) return -1;
    *out_fd = (int)value;
    return 0;
}

static int open_usb_fd(const char *arg, int *out_fd) {
    int fd = -1;
    if (is_number_string(arg)) {
        if (parse_fd_string(arg, &fd) == 0) {
            printf("Using fd from argv[1]=%d\n", fd);
            *out_fd = fd;
            return 0;
        }
    }

    const char *usb_fd_env = getenv("USB_FD");
    if (usb_fd_env && usb_fd_env[0] != '\0') {
        if (parse_fd_string(usb_fd_env, &fd) == 0) {
            printf("Using fd from USB_FD=%d\n", fd);
            *out_fd = fd;
            return 0;
        }
        fprintf(stderr, "Invalid USB_FD value: %s\n", usb_fd_env);
        return -1;
    }

    if (strncmp(arg, "fd:", 3) == 0) {
        if (parse_fd_string(arg + 3, &fd) == 0) {
            printf("Using fd: syntax, fd=%d\n", fd);
            *out_fd = fd;
            return 0;
        }
        fprintf(stderr, "Invalid fd: syntax value: %s\n", arg);
        return -1;
    }

    printf("Opening device path %s\n", arg);
    fd = open(arg, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "open(%s) failed: errno=%d (%s)\n", arg, errno, strerror(errno));
        return -1;
    }
    *out_fd = fd;
    return 0;
}

typedef struct {
    int ifnum;
    int alt;
    int has_in;
    int has_out;
    int endpoint_count;
    int endpoints[16];
    unsigned char ep_addr[16];
    unsigned char ep_attr[16];
    unsigned short ep_maxpkt[16];
} alt_info;

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s /dev/bus/usb/BBB/DDD\n", argv[0]);
        fprintf(stderr, "   or: USB_FD=<fd> %s dummy\n", argv[0]);
        fprintf(stderr, "   or: %s fd:<n>\n", argv[0]);
        return 2;
    }

    int fd = -1;
    if (open_usb_fd(argv[1], &fd) < 0) {
        return 1;
    }

    unsigned char devdesc[18];
    if (ctrl_get_descriptor(fd, 1, 0, devdesc, sizeof(devdesc)) < 0) {
        close(fd);
        return 1;
    }

    printf("\nDevice Descriptor:\n");
    hexdump(devdesc, sizeof(devdesc));
    uint16_t idVendor = devdesc[8] | (devdesc[9] << 8);
    uint16_t idProduct = devdesc[10] | (devdesc[11] << 8);
    printf("VID=0x%04x PID=0x%04x\n", idVendor, idProduct);
    printf("bDeviceClass=%u bDeviceSubClass=%u bDeviceProtocol=%u\n", devdesc[4], devdesc[5], devdesc[6]);

    unsigned char cfg9[9];
    if (ctrl_get_descriptor(fd, 2, 0, cfg9, sizeof(cfg9)) < 0) {
        close(fd);
        return 1;
    }
    int total_len = cfg9[2] | (cfg9[3] << 8);
    if (total_len < 9) {
        fprintf(stderr, "Invalid config descriptor length=%d\n", total_len);
        close(fd);
        return 1;
    }
    printf("\nConfig descriptor total length=%d\n", total_len);

    unsigned char *cfg_all = malloc(total_len);
    if (!cfg_all) {
        fprintf(stderr, "OOM\n");
        close(fd);
        return 1;
    }
    if (ctrl_get_descriptor(fd, 2, 0, cfg_all, total_len) < 0) {
        free(cfg_all);
        close(fd);
        return 1;
    }

    printf("\nConfig Descriptor (raw):\n");
    hexdump(cfg_all, total_len);

    alt_info entries[64];
    int entry_count = 0;
    int off = 0;
    int current_if = -1;
    int current_alt = -1;
    int current_iface_index = -1;

    while (off + 2 <= total_len) {
        unsigned char bLength = cfg_all[off];
        unsigned char bDescriptorType = cfg_all[off + 1];
        if (bLength < 2) break;
        if (off + bLength > total_len) break;

        if (bDescriptorType == 0x04 && bLength >= 9) {
            current_if = cfg_all[off + 2];
            current_alt = cfg_all[off + 3];
            current_iface_index = entry_count;
            if (entry_count < (int)(sizeof(entries)/sizeof(entries[0]))) {
                entries[entry_count].ifnum = current_if;
                entries[entry_count].alt = current_alt;
                entries[entry_count].has_in = 0;
                entries[entry_count].has_out = 0;
                entries[entry_count].endpoint_count = 0;
                entry_count++;
            }
            printf("\nInterface %d\n", current_if);
            printf("  bAlternateSetting=%d\n", current_alt);
            printf("  bInterfaceClass=%u\n", cfg_all[off + 5]);
            printf("  bInterfaceSubClass=%u\n", cfg_all[off + 6]);
            printf("  bInterfaceProtocol=%u\n", cfg_all[off + 7]);
        } else if (bDescriptorType == 0x05 && bLength >= 7) {
            unsigned char bEndpointAddress = cfg_all[off + 2];
            unsigned char bmAttributes = cfg_all[off + 3];
            unsigned short wMaxPacketSize = cfg_all[off + 4] | (cfg_all[off + 5] << 8);
            unsigned char bInterval = cfg_all[off + 6];
            const char *dir = (bEndpointAddress & 0x80) ? "IN" : "OUT";
            const char *type = usb_endpoint_type(bmAttributes);
            printf("    Endpoint 0x%02x\n", bEndpointAddress);
            printf("      type=%s\n", type);
            printf("      direction=%s\n", dir);
            printf("      max packet size=%u\n", wMaxPacketSize);
            printf("      interval=%u\n", bInterval);
            if (current_iface_index >= 0 && current_iface_index < entry_count) {
                alt_info *entry = &entries[current_iface_index];
                if (entry->endpoint_count < 16) {
                    entry->ep_addr[entry->endpoint_count] = bEndpointAddress;
                    entry->ep_attr[entry->endpoint_count] = bmAttributes;
                    entry->ep_maxpkt[entry->endpoint_count] = wMaxPacketSize;
                    entry->endpoint_count++;
                }
                if ((bmAttributes & 0x03) == 2) {
                    if (bEndpointAddress & 0x80) entry->has_in = 1;
                    else entry->has_out = 1;
                }
            }
        }
        off += bLength;
    }

    printf("\nCandidate altsettings with bulk endpoints:\n");
    for (int i = 0; i < entry_count; ++i) {
        if (entries[i].has_in || entries[i].has_out) {
            printf("  interface=%d alt=%d bulk_in=%d bulk_out=%d\n",
                   entries[i].ifnum, entries[i].alt, entries[i].has_in, entries[i].has_out);
            printf("    endpoints:\n");
            for (int j = 0; j < entries[i].endpoint_count; ++j) {
                printf("      0x%02x %s %s maxpkt=%u\n",
                       entries[i].ep_addr[j],
                       usb_endpoint_type(entries[i].ep_attr[j]),
                       (entries[i].ep_addr[j] & 0x80) ? "IN" : "OUT",
                       entries[i].ep_maxpkt[j]);
            }
        }
    }

    for (int i = 0; i < entry_count; ++i) {
        if (!(entries[i].has_in || entries[i].has_out)) continue;
        int ifnum = entries[i].ifnum;
        int alt = entries[i].alt;
        printf("\nTesting interface %d alt %d\n", ifnum, alt);

        if (ioctl(fd, USBDEVFS_CLAIMINTERFACE, &ifnum) < 0) {
            fprintf(stderr, "  USBDEVFS_CLAIMINTERFACE(if=%d) failed: errno=%d (%s)\n", ifnum, errno, strerror(errno));
            continue;
        }
        printf("  Claim succeeded for interface %d\n", ifnum);

        struct usbdevfs_setinterface si;
        si.interface = ifnum;
        si.altsetting = alt;
        if (ioctl(fd, USBDEVFS_SETINTERFACE, &si) < 0) {
            fprintf(stderr, "  USBDEVFS_SETINTERFACE(if=%d alt=%d) failed: errno=%d (%s)\n", ifnum, alt, errno, strerror(errno));
        } else {
            printf("  SetInterface succeeded for interface %d alt %d\n", ifnum, alt);
        }

        int has_bulk_in = 0;
        int bulk_in_ep = -1;
        for (int j = 0; j < entries[i].endpoint_count; ++j) {
            if ((entries[i].ep_attr[j] & 0x03) == 2 && (entries[i].ep_addr[j] & 0x80)) {
                has_bulk_in = 1;
                bulk_in_ep = entries[i].ep_addr[j];
                break;
            }
        }
        if (has_bulk_in) {
            printf("  Attempting raw read from bulk IN 0x%02x\n", bulk_in_ep);
            unsigned char buf[64];
            struct usbdevfs_bulktransfer bulk;
            bulk.ep = bulk_in_ep;
            bulk.len = sizeof(buf);
            bulk.timeout = 1000;
            bulk.data = buf;
            int rr = ioctl(fd, USBDEVFS_BULK, &bulk);
            if (rr < 0) {
                fprintf(stderr, "  USBDEVFS_BULK(if=%d ep=0x%02x) failed: errno=%d (%s)\n", ifnum, bulk_in_ep, errno, strerror(errno));
            } else {
                printf("  Read %d bytes:\n", rr);
                hexdump(buf, rr);
            }
        } else {
            printf("  No bulk IN endpoint in this interface/alt for test\n");
        }

        if (ioctl(fd, USBDEVFS_RELEASEINTERFACE, &ifnum) < 0) {
            fprintf(stderr, "  USBDEVFS_RELEASEINTERFACE(if=%d) failed: errno=%d (%s)\n", ifnum, errno, strerror(errno));
        } else {
            printf("  Released interface %d\n", ifnum);
        }
    }

    free(cfg_all);
    close(fd);
    return 0;
}
