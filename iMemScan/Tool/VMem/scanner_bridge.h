//
//  scanner_bridge.h
//  iMemScanTS
//
//  Bridges VMMemValueType/VMMemComparison <-> ValueType/CompareType
//

#ifndef scanner_bridge_h
#define scanner_bridge_h

#include "scanner_core.h"
#import "VMTypeHeader.h"

static inline ValueType vmtype_to_valuetype(VMMemValueType t) {
    // VMMemValueType starts at 1, ValueType starts at 0, same order
    return (ValueType)(t - 1);
}

static inline CompareType vmcomp_to_comparetype(VMMemComparison c) {
    switch (c) {
        case VMMemComparisonLT: return CMP_DECREASED; // ponytail: LT maps to DECREASED for next-filter semantics
        case VMMemComparisonLE: return CMP_DECREASED;
        case VMMemComparisonEQ: return CMP_EXACT;
        case VMMemComparisonGE: return CMP_INCREASED;
        case VMMemComparisonGT: return CMP_INCREASED;
    }
    return CMP_EXACT;
}

#endif /* scanner_bridge_h */
