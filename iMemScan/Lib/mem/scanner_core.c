//
//  scanner_core.c
//  iMemScanTS
//
//  Platform-agnostic scan state machine ported from ramdaemon.
//  Pure C99, no OS dependencies.
//

#include "scanner_core.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_CANDIDATES 500000

size_t value_type_size(ValueType t) {
    switch (t) {
        case VAL_I8: case VAL_U8: return 1;
        case VAL_I16: case VAL_U16: return 2;
        case VAL_I32: case VAL_U32: case VAL_F32: return 4;
        case VAL_I64: case VAL_U64: case VAL_F64: return 8;
    }
    return 4;
}

int parse_type(const char *s, ValueType *out) {
    struct { const char *name; ValueType t; } table[] = {
        {"i8", VAL_I8}, {"u8", VAL_U8}, {"i16", VAL_I16}, {"u16", VAL_U16},
        {"i32", VAL_I32}, {"u32", VAL_U32}, {"i64", VAL_I64}, {"u64", VAL_U64},
        {"f32", VAL_F32}, {"f64", VAL_F64},
    };
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (strcmp(s, table[i].name) == 0) { *out = table[i].t; return 0; }
    }
    return -1;
}

void parse_value(ValueType type, const char *s, unsigned char *out) {
    int base = (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? 16 : 10;
    switch (type) {
        case VAL_I8:  { int8_t v = (int8_t)strtol(s, NULL, base); memcpy(out, &v, 1); break; }
        case VAL_U8:  { uint8_t v = (uint8_t)strtoul(s, NULL, base); memcpy(out, &v, 1); break; }
        case VAL_I16: { int16_t v = (int16_t)strtol(s, NULL, base); memcpy(out, &v, 2); break; }
        case VAL_U16: { uint16_t v = (uint16_t)strtoul(s, NULL, base); memcpy(out, &v, 2); break; }
        case VAL_I32: { int32_t v = (int32_t)strtol(s, NULL, base); memcpy(out, &v, 4); break; }
        case VAL_U32: { uint32_t v = (uint32_t)strtoul(s, NULL, base); memcpy(out, &v, 4); break; }
        case VAL_I64: { int64_t v = strtoll(s, NULL, base); memcpy(out, &v, 8); break; }
        case VAL_U64: { uint64_t v = strtoull(s, NULL, base); memcpy(out, &v, 8); break; }
        case VAL_F32: { float v = strtof(s, NULL); memcpy(out, &v, 4); break; }
        case VAL_F64: { double v = strtod(s, NULL); memcpy(out, &v, 8); break; }
    }
}

int compare_numeric(ValueType type, const unsigned char *a, const unsigned char *b) {
    switch (type) {
        case VAL_I8:  { int8_t x,y; memcpy(&x,a,1); memcpy(&y,b,1); return (x>y)-(x<y); }
        case VAL_U8:  { uint8_t x,y; memcpy(&x,a,1); memcpy(&y,b,1); return (x>y)-(x<y); }
        case VAL_I16: { int16_t x,y; memcpy(&x,a,2); memcpy(&y,b,2); return (x>y)-(x<y); }
        case VAL_U16: { uint16_t x,y; memcpy(&x,a,2); memcpy(&y,b,2); return (x>y)-(x<y); }
        case VAL_I32: { int32_t x,y; memcpy(&x,a,4); memcpy(&y,b,4); return (x>y)-(x<y); }
        case VAL_U32: { uint32_t x,y; memcpy(&x,a,4); memcpy(&y,b,4); return (x>y)-(x<y); }
        case VAL_I64: { int64_t x,y; memcpy(&x,a,8); memcpy(&y,b,8); return (x>y)-(x<y); }
        case VAL_U64: { uint64_t x,y; memcpy(&x,a,8); memcpy(&y,b,8); return (x>y)-(x<y); }
        case VAL_F32: { float x,y; memcpy(&x,a,4); memcpy(&y,b,4); return (x>y)-(x<y); }
        case VAL_F64: { double x,y; memcpy(&x,a,8); memcpy(&y,b,8); return (x>y)-(x<y); }
    }
    return 0;
}

int result_push(ScanResult *r, uint64_t addr, const unsigned char *value, size_t value_size) {
    if (r->count >= MAX_CANDIDATES) return -1;
    if (r->count == r->capacity) {
        size_t newcap = r->capacity ? r->capacity * 2 : 4096;
        Candidate *tmp = realloc(r->items, sizeof(Candidate) * newcap);
        if (!tmp) return -1;
        r->items = tmp;
        r->capacity = newcap;
    }
    Candidate *c = &r->items[r->count++];
    c->addr = addr;
    memset(c->last_value, 0, sizeof(c->last_value));
    memcpy(c->last_value, value, value_size);
    return 0;
}

void scan_result_free(ScanResult *r) {
    free(r->items);
    r->items = NULL;
    r->count = r->capacity = 0;
}

int scan_result_copy(const ScanResult *src, ScanResult *dst) {
    dst->type = src->type;
    dst->count = dst->capacity = src->count;
    if (src->count == 0) { dst->items = NULL; return 0; }
    dst->items = malloc(sizeof(Candidate) * src->count);
    if (!dst->items) return -1;
    memcpy(dst->items, src->items, sizeof(Candidate) * src->count);
    return 0;
}

void snapshot_free(Snapshot *s) {
    for (size_t i = 0; i < s->count; i++) free(s->regions[i].bytes);
    free(s->regions);
    s->regions = NULL;
    s->count = s->capacity = 0;
}

int snapshot_copy(const Snapshot *src, Snapshot *dst) {
    dst->type = src->type;
    dst->count = dst->capacity = src->count;
    if (src->count == 0) { dst->regions = NULL; return 0; }
    dst->regions = malloc(sizeof(SnapshotRegion) * src->count);
    if (!dst->regions) return -1;
    for (size_t i = 0; i < src->count; i++) {
        dst->regions[i].start = src->regions[i].start;
        dst->regions[i].len = src->regions[i].len;
        dst->regions[i].bytes = malloc(src->regions[i].len);
        if (!dst->regions[i].bytes) { dst->count = i; snapshot_free(dst); return -1; }
        memcpy(dst->regions[i].bytes, src->regions[i].bytes, src->regions[i].len);
    }
    return 0;
}

// --- State machine ---

static void saved_state_free(SavedState *ss) {
    if (ss->kind == DSTATE_CANDIDATES) scan_result_free(&ss->cands);
    else if (ss->kind == DSTATE_SNAPSHOT) snapshot_free(&ss->snap);
    ss->kind = DSTATE_EMPTY;
}

void state_init(ScanState *s) {
    memset(s, 0, sizeof(*s));
    s->kind = DSTATE_EMPTY;
}

void state_reset(ScanState *s) {
    if (s->kind == DSTATE_CANDIDATES) scan_result_free(&s->cands);
    else if (s->kind == DSTATE_SNAPSHOT) snapshot_free(&s->snap);
    for (int i = 0; i < s->history_count; i++) saved_state_free(&s->history[i]);
    state_init(s);
}

static void push_current_to_history(ScanState *s) {
    if (s->kind == DSTATE_EMPTY) return;
    if (s->history_count == HISTORY_LEVELS) {
        saved_state_free(&s->history[HISTORY_LEVELS - 1]);
        memmove(&s->history[1], &s->history[0], sizeof(SavedState) * (HISTORY_LEVELS - 1));
    } else {
        memmove(&s->history[1], &s->history[0], sizeof(SavedState) * s->history_count);
        s->history_count++;
    }
    s->history[0].kind = s->kind;
    if (s->kind == DSTATE_CANDIDATES) {
        scan_result_copy(&s->cands, &s->history[0].cands);
    } else {
        snapshot_copy(&s->snap, &s->history[0].snap);
    }
}

void state_set_candidates(ScanState *s, ScanResult *new_cands) {
    push_current_to_history(s);
    if (s->kind == DSTATE_CANDIDATES) scan_result_free(&s->cands);
    else if (s->kind == DSTATE_SNAPSHOT) snapshot_free(&s->snap);
    s->kind = DSTATE_CANDIDATES;
    s->cands = *new_cands; // ownership transfer
}

void state_set_snapshot(ScanState *s, Snapshot *new_snap) {
    push_current_to_history(s);
    if (s->kind == DSTATE_CANDIDATES) scan_result_free(&s->cands);
    else if (s->kind == DSTATE_SNAPSHOT) snapshot_free(&s->snap);
    s->kind = DSTATE_SNAPSHOT;
    s->snap = *new_snap; // ownership transfer
}

int state_undo(ScanState *s) {
    if (s->history_count == 0) return -1;
    if (s->kind == DSTATE_CANDIDATES) scan_result_free(&s->cands);
    else if (s->kind == DSTATE_SNAPSHOT) snapshot_free(&s->snap);
    s->kind = s->history[0].kind;
    if (s->kind == DSTATE_CANDIDATES) s->cands = s->history[0].cands;
    else s->snap = s->history[0].snap;
    memmove(&s->history[0], &s->history[1], sizeof(SavedState) * (s->history_count - 1));
    s->history_count--;
    return 0;
}
