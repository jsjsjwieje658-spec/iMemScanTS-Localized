//
//  scanner_ios.h
//  iMemScanTS
//
//  iOS/Mach adapter: bridges scanner_core state machine with mach_vm APIs.
//

#ifndef scanner_ios_h
#define scanner_ios_h

#include "scanner_core.h"
#include <mach/mach.h>

// Scan for exact value across all writable regions of task.
// Returns 0 on success, 1 if capped (hit MAX_CANDIDATES), -1 on error.
int ios_scan_first(mach_port_t task, ValueType type, const unsigned char *value, ScanResult *out);

// Filter existing candidates by compare type and optional new value.
int ios_scan_next(mach_port_t task, const ScanResult *prev, CompareType cmp,
                  const unsigned char *value, ScanResult *out);

// Unknown scan: snapshot all writable regions into RAM.
int ios_scan_unknown(mach_port_t task, ValueType type, Snapshot *out);

// Next after unknown: compare current memory against snapshot.
int ios_scan_unknown_next(mach_port_t task, const Snapshot *snap, CompareType cmp, ScanResult *out);

// Filter snapshot by current exact value (ramdaemon: scan <val> after unknown scan).
// Every position captured in the snapshot is tested against the live value.
int ios_scan_snapshot_value(mach_port_t task, const Snapshot *snap, const unsigned char *value, ScanResult *out);

// Read single value from target task.
ssize_t ios_read_value(mach_port_t task, uint64_t addr, void *buf, size_t len);

// Write single value to target task.
ssize_t ios_write_value(mach_port_t task, uint64_t addr, const void *buf, size_t len);

#endif /* scanner_ios_h */
