//
//  freeze_ios.h
//  iMemScanTS
//
//  GCD timer-based value lock (replaces ramdaemon's fork-based freeze).
//

#ifndef freeze_ios_h
#define freeze_ios_h

#include "scanner_core.h"
#include <mach/mach.h>

typedef struct {
    uint64_t addr;
    ValueType type;
    unsigned char value[8];
} FreezeEntry;

typedef struct {
    FreezeEntry *items;
    size_t count;
    size_t capacity;
} FreezeList;

// Start a background GCD timer that writes all entries every ~50ms.
// Returns 0 on success, -1 if already running.
int freeze_start(mach_port_t task, FreezeList *list);

// Stop the background timer. Returns 0 on success, -1 if not running.
int freeze_stop(void);

// Check if freeze timer is active.
int freeze_is_running(void);

void freeze_list_add(FreezeList *list, uint64_t addr, ValueType type, const unsigned char *value);
void freeze_list_remove(FreezeList *list, uint64_t addr);
void freeze_list_free(FreezeList *list);

#endif /* freeze_ios_h */
