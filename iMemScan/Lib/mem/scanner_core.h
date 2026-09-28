//
//  scanner_core.h
//  iMemScanTS
//
//  Platform-agnostic scan state machine ported from ramdaemon.
//  No OS headers — only stdint/stdlib/string.
//

#ifndef scanner_core_h
#define scanner_core_h

#include <stdint.h>
#include <stddef.h>

typedef enum {
    VAL_I8, VAL_U8, VAL_I16, VAL_U16,
    VAL_I32, VAL_U32, VAL_I64, VAL_U64,
    VAL_F32, VAL_F64
} ValueType;

typedef enum {
    CMP_EXACT,
    CMP_CHANGED,
    CMP_UNCHANGED,
    CMP_INCREASED,
    CMP_DECREASED
} CompareType;

typedef struct {
    uint64_t addr;
    unsigned char last_value[8];
} Candidate;

typedef struct {
    Candidate *items;
    size_t count;
    size_t capacity;
    ValueType type;
} ScanResult;

typedef struct {
    uint64_t start;
    uint64_t len;
    unsigned char *bytes;
} SnapshotRegion;

typedef struct {
    ValueType type;
    SnapshotRegion *regions;
    size_t count;
    size_t capacity;
} Snapshot;

#define HISTORY_LEVELS 5

typedef enum { DSTATE_EMPTY, DSTATE_SNAPSHOT, DSTATE_CANDIDATES } DaemonStateKind;

typedef struct {
    DaemonStateKind kind;
    Snapshot snap;
    ScanResult cands;
} SavedState;

typedef struct {
    DaemonStateKind kind;
    Snapshot snap;
    ScanResult cands;
    SavedState history[HISTORY_LEVELS];
    int history_count;
} ScanState;

// --- Type utilities ---
size_t value_type_size(ValueType t);
int parse_type(const char *s, ValueType *out);
void parse_value(ValueType type, const char *s, unsigned char *out);
int compare_numeric(ValueType type, const unsigned char *a, const unsigned char *b);

// --- Result management ---
int result_push(ScanResult *r, uint64_t addr, const unsigned char *value, size_t value_size);
void scan_result_free(ScanResult *r);
int scan_result_copy(const ScanResult *src, ScanResult *dst);
void snapshot_free(Snapshot *s);
int snapshot_copy(const Snapshot *src, Snapshot *dst);

// --- State machine ---
void state_init(ScanState *s);
void state_reset(ScanState *s);
void state_set_candidates(ScanState *s, ScanResult *new_cands);
void state_set_snapshot(ScanState *s, Snapshot *new_snap);
int state_undo(ScanState *s);

#endif /* scanner_core_h */
