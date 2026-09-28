//
//  scanner_ios.m
//  iMemScanTS
//
//  iOS/Mach adapter: uses mach_vm_region_recurse + mach_vm_read_overwrite
//  to drive the platform-agnostic scanner_core state machine.
//
//  Notes vs ramdaemon (Linux/Android):
//  - No pagemap: every readable+writable region is scanned directly.
//  - Submaps are descended into (depth++ without advancing the address) so
//    nested VM maps are neither skipped nor double-counted.
//  - Freeze is handled by freeze_ios.m (GCD timer), not here.
//

#include "scanner_ios.h"
#include <TargetConditionals.h>
#include <string.h>
#include <stdlib.h>

extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
extern kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, pointer_t, mach_msg_type_number_t);
extern kern_return_t mach_vm_region_recurse(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, uint32_t *, vm_region_recurse_info_t, mach_msg_type_number_t *);

#define CHUNK_SIZE (1 << 20) // 1MB read chunks

ssize_t ios_read_value(mach_port_t task, uint64_t addr, void *buf, size_t len) {
    mach_vm_size_t out = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)addr, (mach_vm_size_t)len, (mach_vm_address_t)buf, &out);
    return (kr == KERN_SUCCESS) ? (ssize_t)out : -1;
}

ssize_t ios_write_value(mach_port_t task, uint64_t addr, const void *buf, size_t len) {
    kern_return_t kr = mach_vm_write(task, (mach_vm_address_t)addr, (pointer_t)buf, (mach_msg_type_number_t)len);
    return (kr == KERN_SUCCESS) ? (ssize_t)len : -1;
}

int ios_scan_first(mach_port_t task, ValueType type, const unsigned char *value, ScanResult *out) {
    size_t vsize = value_type_size(type);
    out->items = NULL;
    out->count = 0;
    out->capacity = 0;
    out->type = type;

    mach_vm_address_t address = 0;
    mach_vm_size_t region_size = 0;
    uint32_t depth = 0;
    int capped = 0;

    unsigned char *buf = malloc(CHUNK_SIZE);
    if (!buf) return -1;

    while (!capped) {
        struct vm_region_submap_info_64 info;
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        mach_vm_address_t addr = address;
        kern_return_t kr = mach_vm_region_recurse(task, &addr, &region_size, &depth,
                                                  (vm_region_recurse_info_t)&info, &info_count);
        if (kr != KERN_SUCCESS) break;

        if (info.is_submap) {
            depth++; // descend into submap without advancing address
            continue;
        }

        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) {
            uint64_t offset = 0;
            while (offset < region_size && !capped) {
                size_t want = (size_t)((region_size - offset) < CHUNK_SIZE ? (region_size - offset) : CHUNK_SIZE);
                mach_vm_size_t got = 0;
                kr = mach_vm_read_overwrite(task, addr + offset, (mach_vm_size_t)want, (mach_vm_address_t)buf, &got);
                if (kr != KERN_SUCCESS || got == 0) break;

                for (size_t off = 0; off + vsize <= (size_t)got; off++) {
                    if (memcmp(buf + off, value, vsize) == 0) {
                        if (result_push(out, (uint64_t)addr + offset + off, value, vsize) != 0) {
                            capped = 1;
                            break;
                        }
                    }
                }
                offset += got;
            }
        }

        address = addr + region_size;
    }

    free(buf);
    return capped ? 1 : 0;
}

int ios_scan_next(mach_port_t task, const ScanResult *prev, CompareType cmp,
                  const unsigned char *value, ScanResult *out) {
    size_t vsize = value_type_size(prev->type);
    out->items = NULL;
    out->count = 0;
    out->capacity = 0;
    out->type = prev->type;

    if (prev->count == 0) return 0;

    unsigned char cur[8];
    for (size_t i = 0; i < prev->count; i++) {
        mach_vm_size_t got = 0;
        kern_return_t kr = mach_vm_read_overwrite(task, prev->items[i].addr, (mach_vm_size_t)vsize,
                                                  (mach_vm_address_t)cur, &got);
        if (kr != KERN_SUCCESS || got != vsize) continue;

        int keep = 0;
        switch (cmp) {
            case CMP_EXACT:     keep = (memcmp(cur, value, vsize) == 0); break;
            case CMP_CHANGED:   keep = (memcmp(cur, prev->items[i].last_value, vsize) != 0); break;
            case CMP_UNCHANGED: keep = (memcmp(cur, prev->items[i].last_value, vsize) == 0); break;
            case CMP_INCREASED: keep = compare_numeric(prev->type, cur, prev->items[i].last_value) > 0; break;
            case CMP_DECREASED: keep = compare_numeric(prev->type, cur, prev->items[i].last_value) < 0; break;
        }
        if (keep) result_push(out, prev->items[i].addr, cur, vsize);
    }
    return 0;
}

int ios_scan_unknown(mach_port_t task, ValueType type, Snapshot *out) {
    out->type = type;
    out->regions = NULL;
    out->count = 0;
    out->capacity = 0;

    mach_vm_address_t address = 0;
    mach_vm_size_t region_size = 0;
    uint32_t depth = 0;

    unsigned char *buf = malloc(CHUNK_SIZE);
    if (!buf) return -1;

    while (1) {
        struct vm_region_submap_info_64 info;
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        mach_vm_address_t addr = address;
        kern_return_t kr = mach_vm_region_recurse(task, &addr, &region_size, &depth,
                                                  (vm_region_recurse_info_t)&info, &info_count);
        if (kr != KERN_SUCCESS) break;

        if (info.is_submap) {
            depth++; // descend into submap without advancing address
            continue;
        }

        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) {
            unsigned char *region_buf = malloc((size_t)region_size);
            if (!region_buf) { address = addr + region_size; continue; }

            uint64_t captured = 0;
            uint64_t offset = 0;
            while (offset < region_size) {
                size_t want = (size_t)((region_size - offset) < CHUNK_SIZE ? (region_size - offset) : CHUNK_SIZE);
                mach_vm_size_t got = 0;
                kr = mach_vm_read_overwrite(task, addr + offset, (mach_vm_size_t)want, (mach_vm_address_t)buf, &got);
                if (kr != KERN_SUCCESS || got == 0) break;
                memcpy(region_buf + captured, buf, (size_t)got);
                captured += got;
                offset += got;
            }

            if (captured > 0) {
                if (out->count == out->capacity) {
                    size_t newcap = out->capacity ? out->capacity * 2 : 64;
                    SnapshotRegion *tmp = realloc(out->regions, sizeof(SnapshotRegion) * newcap);
                    if (!tmp) { free(region_buf); break; }
                    out->regions = tmp;
                    out->capacity = newcap;
                }
                SnapshotRegion *sr = &out->regions[out->count++];
                sr->start = (uint64_t)addr;
                sr->len = captured;
                sr->bytes = region_buf;
            } else {
                free(region_buf);
            }
        }

        address = addr + region_size;
    }

    free(buf);
    return 0;
}

int ios_scan_unknown_next(mach_port_t task, const Snapshot *snap, CompareType cmp, ScanResult *out) {
    if (cmp != CMP_CHANGED && cmp != CMP_UNCHANGED && cmp != CMP_INCREASED && cmp != CMP_DECREASED) return -1;

    size_t vsize = value_type_size(snap->type);
    out->type = snap->type;
    out->items = NULL;
    out->count = 0;
    out->capacity = 0;

    unsigned char *new_buf = malloc(CHUNK_SIZE);
    if (!new_buf) return -1;
    int capped = 0;

    for (size_t ri = 0; ri < snap->count && !capped; ri++) {
        const SnapshotRegion *sr = &snap->regions[ri];
        uint64_t off = 0;
        while (off < sr->len && !capped) {
            size_t want = (size_t)((sr->len - off) < CHUNK_SIZE ? (sr->len - off) : CHUNK_SIZE);
            mach_vm_size_t got = 0;
            kern_return_t kr = mach_vm_read_overwrite(task, sr->start + off, (mach_vm_size_t)want,
                                                       (mach_vm_address_t)new_buf, &got);
            if (kr != KERN_SUCCESS || got == 0) { off += want; continue; }

            for (size_t p = 0; p + vsize <= (size_t)got; p++) {
                const unsigned char *o = sr->bytes + off + p;
                const unsigned char *n = new_buf + p;
                int keep = 0;
                switch (cmp) {
                    case CMP_CHANGED:   keep = (memcmp(o, n, vsize) != 0); break;
                    case CMP_UNCHANGED: keep = (memcmp(o, n, vsize) == 0); break;
                    case CMP_INCREASED: keep = compare_numeric(snap->type, n, o) > 0; break;
                    case CMP_DECREASED: keep = compare_numeric(snap->type, n, o) < 0; break;
                    default: break;
                }
                if (keep) {
                    if (result_push(out, sr->start + off + p, n, vsize) != 0) {
                        capped = 1;
                        break;
                    }
                }
            }
            off += got;
        }
    }

    free(new_buf);
    return capped ? 1 : 0;
}

// Filter snapshot by current exact value (ramdaemon: scan <val> after unknown scan).
// Every position captured in the snapshot is tested against the live value.
int ios_scan_snapshot_value(mach_port_t task, const Snapshot *snap, const unsigned char *value, ScanResult *out) {
    size_t vsize = value_type_size(snap->type);
    out->items = NULL;
    out->count = 0;
    out->capacity = 0;
    out->type = snap->type;

    unsigned char *buf = malloc(CHUNK_SIZE);
    if (!buf) return -1;
    int capped = 0;

    for (size_t ri = 0; ri < snap->count && !capped; ri++) {
        const SnapshotRegion *sr = &snap->regions[ri];
        uint64_t off = 0;
        while (off < sr->len && !capped) {
            size_t want = (size_t)((sr->len - off) < CHUNK_SIZE ? (sr->len - off) : CHUNK_SIZE);
            mach_vm_size_t got = 0;
            kern_return_t kr = mach_vm_read_overwrite(task, sr->start + off, (mach_vm_size_t)want,
                                                       (mach_vm_address_t)buf, &got);
            if (kr != KERN_SUCCESS || got == 0) { off += want; continue; }

            for (size_t p = 0; p + vsize <= (size_t)got; p++) {
                if (memcmp(buf + p, value, vsize) == 0) {
                    if (result_push(out, sr->start + off + p, buf + p, vsize) != 0) {
                        capped = 1;
                        break;
                    }
                }
            }
            off += got;
        }
    }

    free(buf);
    return capped ? 1 : 0;
}
