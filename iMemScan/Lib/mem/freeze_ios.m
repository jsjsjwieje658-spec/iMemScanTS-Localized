//
//  freeze_ios.m
//  iMemScanTS
//
//  GCD timer-based value lock. Replaces ramdaemon's fork+nanosleep loop.
//  No daemon process, no socket, no PID file. Pure GCD.
//
//  Ownership: the caller owns the FreezeList (VMTool keeps one ivar for the
//  app lifetime). The timer reads the live list on every tick, so entries
//  added/removed while running take effect immediately.
//

#include "freeze_ios.h"
#include "scanner_ios.h"
#include <dispatch/dispatch.h>
#include <string.h>
#include <stdlib.h>

static dispatch_source_t g_timer = NULL;
static dispatch_queue_t g_queue = NULL;

static void add_locked(FreezeList *list, uint64_t addr, ValueType type, const unsigned char *value) {
    size_t sz = value_type_size(type);
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i].addr == addr) {
            list->items[i].type = type;
            memset(list->items[i].value, 0, 8);
            memcpy(list->items[i].value, value, sz);
            return;
        }
    }
    if (list->count == list->capacity) {
        size_t nc = list->capacity ? list->capacity * 2 : 16;
        FreezeEntry *tmp = realloc(list->items, sizeof(FreezeEntry) * nc);
        if (!tmp) return;
        list->items = tmp;
        list->capacity = nc;
    }
    FreezeEntry *e = &list->items[list->count++];
    e->addr = addr;
    e->type = type;
    memset(e->value, 0, 8);
    memcpy(e->value, value, sz);
}

static void remove_locked(FreezeList *list, uint64_t addr) {
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i].addr == addr) {
            list->items[i] = list->items[list->count - 1];
            list->count--;
            return;
        }
    }
}

void freeze_list_add(FreezeList *list, uint64_t addr, ValueType type, const unsigned char *value) {
    if (g_queue && g_timer) {
        dispatch_sync(g_queue, ^{ add_locked(list, addr, type, value); });
    } else {
        add_locked(list, addr, type, value);
    }
}

void freeze_list_remove(FreezeList *list, uint64_t addr) {
    if (g_queue && g_timer) {
        dispatch_sync(g_queue, ^{ remove_locked(list, addr); });
    } else {
        remove_locked(list, addr);
    }
}

void freeze_list_free(FreezeList *list) {
    free(list->items);
    list->items = NULL;
    list->count = list->capacity = 0;
}

int freeze_is_running(void) {
    return g_timer != NULL ? 1 : 0;
}

int freeze_start(mach_port_t task, FreezeList *list) {
    if (g_timer) return -1; // already running
    if (!list || list->count == 0) return -1;

    g_queue = dispatch_queue_create("com.imemscan.freeze", DISPATCH_QUEUE_SERIAL);
    g_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, g_queue);
    if (!g_timer) { g_queue = NULL; return -1; }

    dispatch_source_set_timer(g_timer, dispatch_time(DISPATCH_TIME_NOW, 0),
                              50 * NSEC_PER_MSEC, 10 * NSEC_PER_MSEC);

    dispatch_source_set_event_handler(g_timer, ^{
        for (size_t i = 0; i < list->count; i++) {
            size_t sz = value_type_size(list->items[i].type);
            ios_write_value(task, list->items[i].addr, list->items[i].value, sz);
        }
    });

    dispatch_resume(g_timer);
    return 0;
}

int freeze_stop(void) {
    if (!g_timer) return -1;
    dispatch_source_t t = g_timer;
    dispatch_queue_t q = g_queue;
    g_timer = NULL;
    g_queue = NULL;
    dispatch_source_cancel(t);
    if (q) dispatch_barrier_sync(q, ^{}); // drain any pending tick/cancel handlers
    return 0;
}
