#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>
#include <linux/usbdevice_fs.h>

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
    if (arg && is_number_string(arg)) {
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

    if (arg && strncmp(arg, "fd:", 3) == 0) {
        if (parse_fd_string(arg + 3, &fd) == 0) {
            printf("Using fd: syntax, fd=%d\n", fd);
            *out_fd = fd;
            return 0;
        }
        fprintf(stderr, "Invalid fd: syntax value: %s\n", arg);
        return -1;
    }

    if (!arg) {
        fprintf(stderr, "No USB path argument provided and USB_FD is not set\n");
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

#define MAX_ALT_ENTRIES 16
#define MAX_ENDPOINTS_PER_ALT 16

typedef struct {
    int ifnum;
    int alt;
    int endpoint_count;
    unsigned char ep_addr[MAX_ENDPOINTS_PER_ALT];
    unsigned char ep_attr[MAX_ENDPOINTS_PER_ALT];
    unsigned short ep_maxpkt[MAX_ENDPOINTS_PER_ALT];
} alt_info;

static int ctrl_get_descriptor(int fd, unsigned char desc_type, unsigned char desc_index, unsigned char *buf, int len) {
    struct usbdevfs_ctrltransfer ctrl;
    memset(&ctrl, 0, sizeof(ctrl));
    ctrl.bRequestType = 0x80;
    ctrl.bRequest = 0x06;
    ctrl.wValue = (desc_type << 8) | desc_index;
    ctrl.wIndex = 0;
    ctrl.wLength = len;
    ctrl.timeout = 1000;
    ctrl.data = buf;

    int r = ioctl(fd, USBDEVFS_CONTROL, &ctrl);
    if (r < 0) {
        return -1;
    }
    return r;
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

static int enumerate_bulk_in_candidates(int fd, alt_info *entries, int max_entries) {
    unsigned char header[9];
    int r = ctrl_get_descriptor(fd, 2, 0, header, sizeof(header));
    if (r < 9) return -1;
    int total_length = header[2] | (header[3] << 8);
    if (total_length <= 0 || total_length > 65536) return -1;

    unsigned char *cfg_all = malloc(total_length);
    if (!cfg_all) return -1;
    r = ctrl_get_descriptor(fd, 2, 0, cfg_all, total_length);
    if (r < total_length) {
        free(cfg_all);
        return -1;
    }

    int current_iface = -1;
    int current_alt = 0;
    int entry_count = 0;
    int off = 0;
    while (off + 2 <= total_length) {
        unsigned char bLength = cfg_all[off];
        unsigned char bDescriptorType = cfg_all[off + 1];
        if (bLength < 2 || off + bLength > total_length) break;

        if (bDescriptorType == 0x04 && bLength >= 9) {
            current_iface = cfg_all[off + 2];
            current_alt = cfg_all[off + 3];
            if (entry_count < max_entries) {
                entries[entry_count].ifnum = current_iface;
                entries[entry_count].alt = current_alt;
                entries[entry_count].endpoint_count = 0;
                entry_count++;
            }
        } else if (bDescriptorType == 0x05 && bLength >= 7 && entry_count > 0) {
            alt_info *entry = &entries[entry_count - 1];
            unsigned char bEndpointAddress = cfg_all[off + 2];
            unsigned char bmAttributes = cfg_all[off + 3];
            unsigned short wMaxPacketSize = cfg_all[off + 4] | (cfg_all[off + 5] << 8);
            if (entry->endpoint_count < MAX_ENDPOINTS_PER_ALT) {
                entry->ep_addr[entry->endpoint_count] = bEndpointAddress;
                entry->ep_attr[entry->endpoint_count] = bmAttributes;
                entry->ep_maxpkt[entry->endpoint_count] = wMaxPacketSize;
                entry->endpoint_count++;
            }
        }

        off += bLength;
    }

    free(cfg_all);
    return entry_count;
}

static void print_hex_ascii(FILE *out, const unsigned char *buf, int len) {
    for (int i = 0; i < len; i += 16) {
        fprintf(out, "%04x: ", i);
        for (int j = 0; j < 16 && i + j < len; ++j) {
            fprintf(out, "%02x ", buf[i+j]);
        }
        fprintf(out, "  ");
        for (int j = 0; j < 16 && i + j < len; ++j) {
            unsigned char c = buf[i+j];
            fprintf(out, "%c", (c >= 32 && c <= 126) ? c : '.');
        }
        fprintf(out, "\n");
    }
}

static void log_line(FILE *out, const char *label, const unsigned char *buf, int len, struct timeval *tv) {
    struct tm tm;
    localtime_r(&tv->tv_sec, &tm);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(out, "[%s.%06ld] %s bytes=%d\n", timebuf, (long)tv->tv_usec, label, len);
    if (len > 0) {
        fprintf(out, "first16:");
        int first = len < 16 ? len : 16;
        for (int i = 0; i < first; ++i) fprintf(out, " %02x", buf[i]);
        fprintf(out, "\n");
        print_hex_ascii(out, buf, len);
    }
    fflush(out);
}

int main(int argc, char **argv) {
    const char *usb_arg = argc >= 2 ? argv[1] : NULL;
    if (!usb_arg && !getenv("USB_FD")) {
        fprintf(stderr, "Usage: %s <fd|fd:<n>|/dev/bus/usb/BBB/DDD> [out.log]\n", argv[0]);
        fprintf(stderr, "       or run under termux-usb -e with USB_FD set\n");
        return 2;
    }

    int fd = -1;
    if (open_usb_fd(usb_arg, &fd) < 0) {
        return 1;
    }

    const char *log_path = argc >= 3 ? argv[2] : "usb_console_dump.log";
    FILE *out = fopen(log_path, "w");
    if (!out) {
        perror("fopen");
        if (fd >= 0) close(fd);
        return 1;
    }

    fprintf(out, "USB console dump log\n");
    fprintf(out, "fd=%d\n", fd);
    fflush(out);

    alt_info entries[MAX_ALT_ENTRIES];
    int entry_count = enumerate_bulk_in_candidates(fd, entries, MAX_ALT_ENTRIES);
    if (entry_count < 0) {
        fprintf(out, "Could not read configuration descriptor\n");
    } else {
        fprintf(out, "Found %d candidate interface/altsettings with bulk endpoints:\n", entry_count);
        for (int i = 0; i < entry_count; ++i) {
            fprintf(out, "  interface=%d alt=%d endpoints=%d\n", entries[i].ifnum, entries[i].alt, entries[i].endpoint_count);
            for (int j = 0; j < entries[i].endpoint_count; ++j) {
                fprintf(out, "    ep=0x%02x type=%s dir=%s maxpkt=%u\n",
                        entries[i].ep_addr[j],
                        usb_endpoint_type(entries[i].ep_attr[j]),
                        (entries[i].ep_addr[j] & 0x80) ? "IN" : "OUT",
                        entries[i].ep_maxpkt[j]);
            }
        }
    }

    int ifnum = 1;
    int ep = 0x81;
    if (entry_count > 0) {
        int found = 0;
        for (int i = 0; i < entry_count && !found; ++i) {
            for (int j = 0; j < entries[i].endpoint_count; ++j) {
                if ((entries[i].ep_attr[j] & 0x03) == 2 && (entries[i].ep_addr[j] & 0x80)) {
                    if (entries[i].ep_addr[j] == 0x81) {
                        ifnum = entries[i].ifnum;
                        ep = entries[i].ep_addr[j];
                        found = 1;
                        break;
                    }
                }
            }
        }
        if (!found) {
            for (int i = 0; i < entry_count && !found; ++i) {
                for (int j = 0; j < entries[i].endpoint_count; ++j) {
                    if ((entries[i].ep_attr[j] & 0x03) == 2 && (entries[i].ep_addr[j] & 0x80)) {
                        ifnum = entries[i].ifnum;
                        ep = entries[i].ep_addr[j];
                        found = 1;
                        break;
                    }
                }
            }
        }
        fprintf(out, "Selected interface=%d endpoint=0x%02x\n", ifnum, ep);
    } else {
        fprintf(out, "Falling back to interface=1 endpoint=0x81\n");
    }
    fflush(out);

    if (ioctl(fd, USBDEVFS_CLAIMINTERFACE, &ifnum) < 0) {
        fprintf(stderr, "USBDEVFS_CLAIMINTERFACE failed: errno=%d (%s)\n", errno, strerror(errno));
        fprintf(out, "USBDEVFS_CLAIMINTERFACE failed: errno=%d (%s)\n", errno, strerror(errno));
        fclose(out);
        if (fd >= 0) close(fd);
        return 1;
    }
    fprintf(out, "Claimed interface %d\n", ifnum);
    fflush(out);

    struct usbdevfs_setinterface si;
    si.interface = ifnum;
    si.altsetting = 1;
    if (ioctl(fd, USBDEVFS_SETINTERFACE, &si) < 0) {
        fprintf(stderr, "USBDEVFS_SETINTERFACE failed: errno=%d (%s)\n", errno, strerror(errno));
        fprintf(out, "USBDEVFS_SETINTERFACE failed: errno=%d (%s)\n", errno, strerror(errno));
        ioctl(fd, USBDEVFS_RELEASEINTERFACE, &ifnum);
        fclose(out);
        close(fd);
        return 1;
    }
    fprintf(out, "Set interface %d altsetting %d\n", ifnum, si.altsetting);
    fflush(out);

    unsigned char buf[512];
    struct usbdevfs_bulktransfer bulk;
    bulk.ep = ep;
    bulk.len = sizeof(buf);
    bulk.timeout = 1000;
    bulk.data = buf;

    struct timeval start, now;
    gettimeofday(&start, NULL);
    int iteration = 0;
    while (1) {
        gettimeofday(&now, NULL);
        long elapsed = now.tv_sec - start.tv_sec;
        if (elapsed >= 60) break;

        int rr = ioctl(fd, USBDEVFS_BULK, &bulk);
        gettimeofday(&now, NULL);
        iteration++;
        if (rr < 0) {
            fprintf(out, "[%ld.%06ld] BULK read failed: errno=%d (%s)\n",
                    now.tv_sec, (long)now.tv_usec, errno, strerror(errno));
            fflush(out);
            if (errno == ETIMEDOUT) {
                continue;
            }
            break;
        }
        log_line(out, "BULK_IN", buf, rr, &now);
    }

    if (ioctl(fd, USBDEVFS_RELEASEINTERFACE, &ifnum) < 0) {
        fprintf(stderr, "USBDEVFS_RELEASEINTERFACE failed: errno=%d (%s)\n", errno, strerror(errno));
        fprintf(out, "USBDEVFS_RELEASEINTERFACE failed: errno=%d (%s)\n", errno, strerror(errno));
    } else {
        fprintf(out, "Released interface %d\n", ifnum);
    }

    fclose(out);
    close(fd);
    return 0;
}
