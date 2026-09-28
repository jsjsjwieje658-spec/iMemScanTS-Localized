//
//  VMTool.m
//  ViewMem
//
//  Created by HaoCold on 2020/8/26.
//  Copyright © 2020 HaoCold. All rights reserved.
//

#import "VMTool.h"
#import "MemModel.h"
//#import "MemRecordModel.h"
//#import "VMAlertTool.h"
#include "mem.h"
#include "scanner_ios.h"
#include "scanner_bridge.h"
#include "freeze_ios.h"
#import "VMOneKeyModel.h"
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import "JHLog.h"
#import "SetModel.h"
#import "YYModel.h"

#define MaxResultCount  1100000

#define kSearchRange @"kSearchRange"
#define kAddrRangelow @"kAddrRangelow"
#define kAddrRangeupp @"kAddrRangeupp"
#define kLimitCount @"kLimitCount"
#define kDuration @"kDuration"
#define kDuration1 @"kDuration1"

typedef struct _addrRangestart{
    uint64_t start;
}AddrRangestart;

typedef struct _addrRangeend{
    uint64_t end;
}AddrRangeend;

typedef struct _range{
    int _rangeend;
}Range;

@interface VMTool()
{
    mach_port_t g_task;
    search_result_chain_t g_chain;
    int g_type;
    //search_result_t *_chainArray;
    int _chainCount;
    Range _range;
    AddrRangestart _addrRangestart;
    AddrRangeend _addrRangeend;
    VMMemValueType _type;
    NSInteger _limitCount;
    NSInteger _duration;
    NSInteger _duration1;

    // 当前搜索结果
    NSArray *_currentResult;
    // 0-数值，1-邻近
    NSInteger _searchType;

    // ramdaemon-style scan state (unknown scan / next filter / undo)
    ScanState _scanState;
    FreezeList _freezeList;
}
@property (nonatomic,  assign) int  pid;
@end

@implementation VMTool

OBJC_EXTERN CFStringRef MGCopyAnswer(CFStringRef key) WEAK_IMPORT_ATTRIBUTE;

+ (instancetype)share
{
    static VMTool *tool;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        tool = [[VMTool alloc] init];
    });
    return tool;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        //g_task = mach_task_self();
        g_chain = NULL;
        g_type = SearchResultValueTypeUndef;
        state_init(&_scanState);
        
#if 1
        NSString *path = @"/var/mobile/Media/iMemScan(Script)/Set.data";
        NSString *string = [[NSString alloc] initWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
        if (string == nil && string.length == 0) {
            _range._rangeend = 0x20;
            _addrRangestart.start = 0x100000000;
            _addrRangeend.end = 0x160000000;
            _limitCount = 1000000;
            _duration = 100;
            _duration1 = 20;
        }else{
            SetModel *model = [SetModel yy_modelWithJSON:string];
            _range._rangeend = (int)strtol([model.range UTF8String], NULL, 16);
            _addrRangestart.start = (int64_t)strtol([model.addrRangeStart UTF8String], NULL, 16);
            _addrRangeend.end = (int64_t)strtol([model.addrRangeEnd UTF8String], NULL, 16);
            _limitCount = [model.LimitCount integerValue];
            _duration = [model.duration integerValue];
            _duration1 = [model.duration1 integerValue];
        }
#else
        NSArray *range = [[NSUserDefaults standardUserDefaults] arrayForKey:kSearchRange];
        if (range.count == 0) {
            _range._rangeend = 0x20;
        }else{
            _range._rangeend = [range[0] intValue];
        }
        
        NSArray *low = [[NSUserDefaults standardUserDefaults] arrayForKey:kAddrRangelow];
        if (low.count == 0) {
            _addrRangestart.start = 0x100000000;
        }else{
            _addrRangestart.start = [low[0] unsignedLongLongValue];
        }
        
        NSArray *upp = [[NSUserDefaults standardUserDefaults] arrayForKey:kAddrRangeupp];
        if (upp.count == 0) {
            _addrRangeend.end = 0x160000000;
        }else{
            _addrRangeend.end = [upp[0] unsignedLongLongValue];
        }
        
        _limitCount = [[[NSUserDefaults standardUserDefaults] objectForKey:kLimitCount] integerValue];
        if (_limitCount == 0) {
            _limitCount = 1000000;
        }
        
        _duration = [[[NSUserDefaults standardUserDefaults] objectForKey:kDuration] integerValue];
        if (_duration == 0) {
            _duration = 100;
        }
        
        _duration1 = [[[NSUserDefaults standardUserDefaults] objectForKey:kDuration1] integerValue];
        if (_duration1 == 0) {
            _duration1 = 20;
        }
#endif
    }
    
    return self;
}

- (void)setPid:(int)pid name:(NSString *)name {
    _pid = pid;
    g_task = get_task(pid, name);
}

- (mach_port_t)getTask
{
    //NSLog(@"*** g_task: %i", g_task);
    return g_task;
}

#pragma mark - public
- (void)nearMemSearch:(NSString *)value type:(VMMemValueType)type range:(int)range callback:(nonnull VMToolSearchBlock)block
{
    _type = type;
    _searchType = 1;
    const char *v = [value UTF8String];
    int t = [self memTypeFromVMMemValueType:type];
    [self _nearMemSearch:v type:t range:range callback:block];
}

- (void)searchValue:(NSString *)value type:(VMMemValueType)type comparison:(VMMemComparison)comparison callback:(nonnull VMToolSearchBlock)block
{
    _type = type;
    _searchType = 0;
    const char *v = [value UTF8String];
    int t = [self memTypeFromVMMemValueType:type];
    int c = [self memComparisonFromVMMemComparison:comparison];
    [self _searchMem:v type:t comparison:c callback:block];
}

- (void)modifyValue:(NSString *)value address:(NSString *)addr type:(VMMemValueType)type
{
    mach_vm_address_t a = 0;
    NSScanner *scanner = [NSScanner scannerWithString:addr];
    if ([addr hasPrefix:@"0x"] || [addr hasPrefix:@"0X"]) {
        [scanner scanHexLongLong:&a];
    }else{
        a = [addr longLongValue];
    }
    
    //if (![scanner scanHexLongLong:&a]) return;
    const char *v = [value UTF8String];
    int t = [self memTypeFromVMMemValueType:type];
    [self _modifyMem:a value:v type:t];
}

- (void)reset
{
    destroy_all_search_result_chain(g_chain);
    g_chain = NULL;
    state_reset(&_scanState);
    freeze_stop();
    freeze_list_free(&_freezeList);
}

- (void)refreshWithCallback:(VMToolSearchBlock)block
{
    if (g_chain == NULL && _scanState.kind != DSTATE_CANDIDATES) {
        block(0, @[]);
        return;
    }
    
    __weak typeof(self) ws = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __strong typeof(ws) ss = ws;

        if (ss->g_chain != NULL) {
            review_mem_in_chain(ss->g_task, ss->g_chain);
        } else if (ss->_scanState.kind == DSTATE_CANDIDATES) {
            // Engine ramdaemon: cap nhat gia tri hien hanh cua candidates (khong loc bot)
            size_t vsize = value_type_size(ss->_scanState.cands.type);
            for (size_t i = 0; i < ss->_scanState.cands.count; i++) {
                unsigned char cur[8];
                ssize_t got = ios_read_value(ss->g_task, ss->_scanState.cands.items[i].addr, cur, vsize);
                if (got == (ssize_t)vsize) {
                    memcpy(ss->_scanState.cands.items[i].last_value, cur, vsize);
                }
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            if (ss->g_chain != NULL) {
                [ss updateChainArray:ss->g_chain count:ss->_chainCount callback:block];
            } else {
                ss->_type = (VMMemValueType)(ss->_scanState.cands.type + 1);
                [ss updateScanStateArray:(NSInteger)ss->_scanState.cands.count callback:block];
            }
        });
    });
}

#pragma mark - ramdaemon-style advanced scan

// Buoc 1 (unknown): chup toan bo vung ghi duoc vao RAM — chua can biet gia tri
- (void)scanUnknown:(VMMemValueType)type callback:(VMToolSearchBlock)block
{
    // Hai engine loai tru nhau: bat dau luong unknown thi huy ket qua chain cu
    destroy_all_search_result_chain(g_chain);
    g_chain = NULL;
    _chainCount = 0;
    _type = type;
    _searchType = 0;
    ValueType t = vmtype_to_valuetype(type);

    __weak typeof(self) ws = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __strong typeof(ws) ss = ws;
        Snapshot snap;
        int rc = ios_scan_unknown(ss->g_task, t, &snap);
        if (rc == 0) {
            state_set_snapshot(&ss->_scanState, &snap);
        } else {
            snapshot_free(&snap);
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            // count = -1: da chup snapshot (kiem tra bang scanStateKind)
            if (block) block(rc == 0 ? -1 : 0, @[]);
        });
    });
}

// Buoc 2+: loc theo thay doi so voi buoc truoc (changed/unchanged/tang/giam)
- (void)nextFilter:(VMMemNextFilter)filter callback:(VMToolSearchBlock)block
{
    _searchType = 0;
    CompareType cmp = CMP_CHANGED;
    switch (filter) {
        case VMMemNextFilterUnchanged: cmp = CMP_UNCHANGED; break;
        case VMMemNextFilterIncreased: cmp = CMP_INCREASED; break;
        case VMMemNextFilterDecreased: cmp = CMP_DECREASED; break;
        case VMMemNextFilterChanged:
        default: break;
    }

    __weak typeof(self) ws = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __strong typeof(ws) ss = ws;
        NSInteger count = 0;

        if (ss->_scanState.kind == DSTATE_SNAPSHOT) {
            ScanResult out;
            if (ios_scan_unknown_next(ss->g_task, &ss->_scanState.snap, cmp, &out) >= 0) {
                state_set_candidates(&ss->_scanState, &out);
                count = (NSInteger)out.count;
            }
        } else if (ss->_scanState.kind == DSTATE_CANDIDATES) {
            ScanResult out;
            if (ios_scan_next(ss->g_task, &ss->_scanState.cands, cmp, NULL, &out) >= 0) {
                state_set_candidates(&ss->_scanState, &out);
                count = (NSInteger)out.count;
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            ss->_type = (VMMemValueType)(ss->_scanState.cands.type + 1);
            [ss updateScanStateArray:count callback:block];
        });
    });
}

// Buoc 2+: loc theo gia tri chinh xac
- (void)nextValue:(NSString *)value callback:(VMToolSearchBlock)block
{
    _searchType = 0;

    __weak typeof(self) ws = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __strong typeof(ws) ss = ws;
        NSInteger count = 0;

        if (ss->_scanState.kind == DSTATE_CANDIDATES) {
            const char *v = [value UTF8String];
            unsigned char bytes[8] = {0};
            parse_value(ss->_scanState.cands.type, v, bytes);
            ScanResult out;
            if (ios_scan_next(ss->g_task, &ss->_scanState.cands, CMP_EXACT, bytes, &out) >= 0) {
                state_set_candidates(&ss->_scanState, &out);
                count = (NSInteger)out.count;
            }
        } else if (ss->_scanState.kind == DSTATE_SNAPSHOT) {
            // ramdaemon: scan <val> ngay sau unknown scan -> loc snapshot theo gia tri hien tai
            const char *v = [value UTF8String];
            unsigned char bytes[8] = {0};
            parse_value(ss->_scanState.snap.type, v, bytes);
            ScanResult out;
            if (ios_scan_snapshot_value(ss->g_task, &ss->_scanState.snap, bytes, &out) >= 0) {
                state_set_candidates(&ss->_scanState, &out);
                count = (NSInteger)out.count;
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            ss->_type = (VMMemValueType)(ss->_scanState.cands.type + 1);
            [ss updateScanStateArray:count callback:block];
        });
    });
}

// Hoan tac 1 buoc loc (toi da 5 muc lich su, nhu ramdaemon)
- (BOOL)undoScan
{
    return state_undo(&_scanState) == 0;
}

- (DaemonStateKind)scanStateKind
{
    return _scanState.kind;
}

- (BOOL)hasScanState
{
    return _scanState.kind != DSTATE_EMPTY;
}

#pragma mark - freeze (GCD timer)

- (BOOL)freezeValue:(NSString *)value address:(NSString *)address type:(VMMemValueType)type
{
    uint64_t a = [self addressFromString:address];
    ValueType t = vmtype_to_valuetype(type);
    unsigned char bytes[8] = {0};
    parse_value(t, [value UTF8String], bytes);

    freeze_list_add(&_freezeList, a, t, bytes);
    if (freeze_is_running()) return YES;
    return freeze_start(g_task, &_freezeList) == 0;
}

- (void)unfreezeValue:(NSString *)address
{
    uint64_t a = [self addressFromString:address];
    freeze_list_remove(&_freezeList, a);
}

- (void)unfreezeAll
{
    freeze_stop();
    freeze_list_free(&_freezeList);
}

- (BOOL)freezing
{
    return freeze_is_running() == 1;
}

// Build mang MemModel tu ScanState.cands (tuong duong updateChainArray nhung cho mang contiguous)
- (void)updateScanStateArray:(NSInteger)count callback:(VMToolSearchBlock)block
{
    NSLog(@"memlog: 结果数量: %@", @(count));

    NSMutableArray *marr = @[].mutableCopy;

    if (_scanState.kind == DSTATE_CANDIDATES &&
        _scanState.cands.count > 0 &&
        (NSInteger)_scanState.cands.count <= MaxResultCount) {
        for (size_t i = 0; i < _scanState.cands.count; i++) {
            Candidate *c = &_scanState.cands.items[i];
            MemModel *model = [[MemModel alloc] init];
            model.o_addr = c->addr;
            model.value = [self valueStringFromBytes:c->last_value type:_scanState.cands.type];
            model.type = _type;
            if (_searchType == 0) [marr addObject:model];
            if (_searchType == 1) if (![marr containsObject:model]) [marr addObject:model];
        }

        [marr sortUsingComparator:^NSComparisonResult(MemModel *obj1, MemModel *obj2) {
            return [obj1.address compare:obj2.address];
        }];
    }

    _currentResult = marr;

    if (block) {
        block(count, marr);
    }
}

- (uint64_t)addressFromString:(NSString *)str
{
    mach_vm_address_t a = 0;
    NSScanner *scanner = [NSScanner scannerWithString:str];
    if ([str hasPrefix:@"0x"] || [str hasPrefix:@"0X"]) {
        [scanner scanHexLongLong:&a];
    } else {
        if (![scanner scanUnsignedLongLong:&a]) {
            a = (mach_vm_address_t)[str longLongValue];
        }
    }
    return (uint64_t)a;
}

- (NSString *)valueStringFromBytes:(const unsigned char *)bytes type:(ValueType)type
{
    switch (type) {
        case VAL_U8:  { uint8_t v;  memcpy(&v, bytes, 1); return [NSString stringWithFormat:@"%u", v]; }
        case VAL_I8:  { int8_t v;   memcpy(&v, bytes, 1); return [NSString stringWithFormat:@"%d", v]; }
        case VAL_U16: { uint16_t v; memcpy(&v, bytes, 2); return [NSString stringWithFormat:@"%u", v]; }
        case VAL_I16: { int16_t v;  memcpy(&v, bytes, 2); return [NSString stringWithFormat:@"%d", v]; }
        case VAL_U32: { uint32_t v; memcpy(&v, bytes, 4); return [NSString stringWithFormat:@"%u", v]; }
        case VAL_I32: { int32_t v;  memcpy(&v, bytes, 4); return [NSString stringWithFormat:@"%d", v]; }
        case VAL_U64: { uint64_t v; memcpy(&v, bytes, 8); return [NSString stringWithFormat:@"%llu", v]; }
        case VAL_I64: { int64_t v;  memcpy(&v, bytes, 8); return [NSString stringWithFormat:@"%lld", v]; }
        case VAL_F32: { float v;    memcpy(&v, bytes, 4); return [NSString stringWithFormat:@"%.7g", v]; }
        case VAL_F64: { double v;   memcpy(&v, bytes, 8); return [NSString stringWithFormat:@"%.15le", v]; }
    }
    return @"0";
}

- (NSArray *)memory:(NSString *)address size:(NSString *)size type:(VMMemSearchType)type valueType:(VMMemValueType)valueType
{
    mach_vm_address_t a = 0;
    NSScanner *scanner = [NSScanner scannerWithString:address];
    if (![scanner scanHexLongLong:&a]) return @[];
    
    int s = [size intValue];
    mach_vm_address_t addr = 0;
    mach_vm_size_t data_size = 0;
    void *data = read_range_mem(g_task, a, s, s, &addr, &data_size);
    if (data == NULL || size == 0) return @[];
    
    NSMutableArray *marr = @[].mutableCopy;
    NSString *hex = @"";
    NSMutableString *val = @"".mutableCopy;
    
    hex = [NSString stringWithFormat:@"%08llX", addr];
    for (mach_vm_size_t i = 0; i < data_size; ++i) {
        
        if (i > 0 && i % type == 0) {
            
            NSArray *arr = [val componentsSeparatedByString:@" "].reverseObjectEnumerator.allObjects;
            
            //
            MemModel *model = [[MemModel alloc] init];
            model.address = hex;
            model.value_16 = [arr componentsJoinedByString:@""];
            model.valueType = valueType;
            [marr addObject:model];
            
            //
            hex = [NSString stringWithFormat:@"0x%08llX", addr + i];
            [val setString:@""];
        }
        
        uint8_t v = *(((uint8_t *)data) + i);
        [val appendFormat:@"%02X ", v];
    }
    
    return marr;
}

- (void)save:(id)obj key:(NSString *)key
{
    [[NSUserDefaults standardUserDefaults] setObject:obj forKey:key];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (int)rangeValue
{
    return _range._rangeend;
}

- (NSString *)rangeStringValue
{
    NSString *range = [NSString stringWithFormat:@"0x%0lX", (long)_range._rangeend];
    return range;
}

- (void)setRange:(NSString *)range
{
    if ([[range uppercaseString] hasPrefix:@"0X"]) {
        _range._rangeend = (int)strtol([range UTF8String], NULL, 16);
    }else{
        _range._rangeend = [range intValue];
    }
    
    [self save:@[@(_range._rangeend)] key:kSearchRange];
}

- (uint64_t)addrLowValue
{
    return _addrRangestart.start;
}

- (NSString *)addrRange
{
    NSString *lowVal = [NSString stringWithFormat:@"0x%0lX", (long)_addrRangestart.start];
    return lowVal;
}

- (void)setAddrRange:(NSString *)low
{
    if ([[low uppercaseString] hasPrefix:@"0X"]) {
        _addrRangestart.start = (int64_t)strtoull([low UTF8String], NULL, 16);
    }else{
        _addrRangestart.start = (int64_t)strtoull([low UTF8String], NULL, 10);
    }
    
    [self save:@[@(_addrRangestart.start)] key:kAddrRangelow];
}

- (uint64_t)addrUppValue
{
    return _addrRangeend.end;
}

- (NSString *)addrRangeUpp
{
    NSString *UppVal = [NSString stringWithFormat:@"0x%0lX", (long)_addrRangeend.end];
    return UppVal;
}

- (void)setAddrRangeUpp:(NSString *)Upp
{
    if ([[Upp uppercaseString] hasPrefix:@"0X"]) {
        _addrRangeend.end = (int64_t)strtoull([Upp UTF8String], NULL, 16);
    }else{
        _addrRangeend.end = (int64_t)strtoull([Upp UTF8String], NULL, 10);
    }
    
    [self save:@[@(_addrRangeend.end)] key:kAddrRangeupp];
}


- (void)setLimitCount:(NSString *)count
{
    _limitCount = [count integerValue];
    
    [self save:@(_limitCount) key:kLimitCount];
}

- (NSInteger)limitCount
{
    return _limitCount;
}

- (void)setDuration:(NSString *)duration
{
    _duration = [duration integerValue];
    
    [self save:@(_duration) key:kDuration];
}

- (NSInteger)duration
{
    return _duration;
}

- (void)setDuration1:(NSString *)duration
{
    _duration1 = [duration integerValue];
    
    [self save:@(_duration1) key:kDuration1];
}

- (NSInteger)duration1
{
    return _duration1;
}

- (NSArray *)allKeys
{
    return @[@"F32",@"F64",@"I8",@"I16",@"I32",@"I64"];
}

- (NSDictionary *)keyValues
{
    return @{@"I8":@(VMMemValueTypeSignedByte),
             @"I16":@(VMMemValueTypeSignedShort),
             @"I32":@(VMMemValueTypeSignedInt),
             @"I64":@(VMMemValueTypeSignedLong),
             @"F32":@(VMMemValueTypeFloat),
             @"F64":@(VMMemValueTypeDouble),
             };
}

- (void)modifyWithArray:(NSArray *)array value:(NSString *)value indexs:(NSString *)indexs open:(BOOL)open
{
    
     // value  >>>>> 1 这是数据修改值
     // indexs >>>>> 1,2,3,4(-0x214) 这是得到的数据结果排序，比如修改第几个
     // open   >>>>>  批量定时循环修改
     
     // 取indexs值
     // -1  >>>>> 全部修改
     // 1,3 >>>>> 修改第1个和第3个
     // 1=10 >>>>> 从第1个修改到第10个
     // 1++10&&ABC >>>>> 从第1个修改到第10个，并修改内存址址尾数带有ABC的关键词
     // @A >>>>> 修改内存址址尾数带有A的关键词
     // ||1024 >>>>> 修改结果数据的数值带有1024的
     
     // 需要计算偏移量
     // -214 或者  +214
     // 例如: 1,3@@-214 参数解释: 1,3表示修改第1个和第3个，但修改前要先计算 -214
     
     // 1. 0x11f9285d0 – 214 = 0x11f9283bc  0x11f9283bc >>> 等于是计算过后的地址
     // 那么修改的时候直接拿计算过后的地址
     // [[VMTool share] modifyValue:model.value address:0x11f9283bc type:model.type];
     
    // 找到目标
    NSMutableArray *marr = @[].mutableCopy;
    if (indexs.length > 0) {
        
        if ([indexs isEqualToString:@"-1"]) {
            [marr addObjectsFromArray:array];
        }
        else if ([indexs containsString:@"//"]) {
            // 1,3@@-214
            NSArray *arr = [indexs componentsSeparatedByString:@"//"];
            if (arr.count == 2) {
                NSString *str1 = arr[0]; // 1,3
                NSString *str2 = arr[1]; // -214
                
                //NSLog(@"memlog: 偏移量 = %@", str2);
                
                // 所有
                if ([str1 isEqualToString:@"-1"]) {
                    [marr addObjectsFromArray:array];
                }else{
                    // 选出要修改的模型
                    NSArray *count = [str1 componentsSeparatedByString:@","];
                    for (NSString *idx in count) {
                        MemModel *model = array[idx.integerValue -1];
                        [marr addObject:model];
                    }
                }
                
                for (MemModel *model in marr) {
                    // 计算地址偏移
                    // string -> unsigned long long
                    NSString *addr = model.address;
                    
                    mach_vm_address_t a = 0;
                    NSScanner *scanner = [NSScanner scannerWithString:addr];
                    if ([addr hasPrefix:@"0x"] || [addr hasPrefix:@"0X"]) {
                        [scanner scanHexLongLong:&a];
                    }else{
                        [scanner scanUnsignedLongLong:&a];
                    }
                    
                    //NSLog(@"memlog: a 计算前 = Hex value: %p / Decimal value: %llu", a, a);
                     
                    mach_vm_address_t b = 0;
                    NSString *symb = [str2 substringToIndex:1]; // + , -
                    NSString *strB = [str2 substringFromIndex:1]; // 数值
                    NSScanner *scannerB = [NSScanner scannerWithString:strB];
                    [scannerB scanHexLongLong:&b];
                    
                    // 偏移
                    if ([symb isEqualToString:@"-"]) {
                        a -= b;
                    }else{
                        a += b;
                    }
                    
                    model.address = @(a).stringValue;
                    
                    //NSLog(@"memlog: a 计算后 = Hex value: %p / Decimal value: %llu", a, a);
                }
            }
        }
        else if ([indexs containsString:@"="]) {
            for (int index=0;  index<=array.count; index++)
            {
                NSInteger start = [[[indexs componentsSeparatedByString:@"="] firstObject] integerValue] -1;
                NSInteger end = [[[indexs componentsSeparatedByString:@"="] lastObject] integerValue] -1;
                if (index >= start && index <= end) {
                    [marr addObject:array[index]];
                }
            }
        }
        else if([indexs containsString:@"@"] ){
            NSMutableArray *ma = [indexs componentsSeparatedByString:@"@"].mutableCopy;
            [ma removeObject:@""];
            
            for (MemModel *model in array) {
                for (NSString *subStr in ma) {
                    if ([[model.address uppercaseString] hasSuffix:[subStr uppercaseString]]) {
                        [marr addObject:model];
                    }
                }
            }
        }
        else if([indexs containsString:@"||"] ){
            NSMutableArray *ma = [indexs componentsSeparatedByString:@"||"].mutableCopy;
            [ma removeObject:@""];
            
            for (MemModel *model in array) {
                for (NSString *subStr in ma) {
                    if ([model.value isEqualToString:subStr]) {
                        [marr addObject:model];
                    }
                }
            }
        }
        else if([indexs containsString:@"++"] && [indexs containsString:@"&&"] ){
            
            // 组合,例如：1++10&&ABC&&B74，
            // 修改第1到第10个
            // 全部结果内存地址中出现尾数包含ABC，B74一率并修改
            
            NSArray *arr = [indexs componentsSeparatedByString:@"&&"];
            NSInteger start = 0;
            NSInteger end = 0;
            
            NSMutableArray *ma = @[].mutableCopy;
            for (int i = 0; i < arr.count; i++) {
                NSString *subStr = [arr objectAtIndex:i];
                if ([subStr containsString:@"++"]) {
                    NSArray *a = [subStr componentsSeparatedByString:@"++"];
                    start = [[a firstObject] integerValue] - 1;
                    end = [[a lastObject] integerValue] - 1;
                }else{
                    [ma addObject:subStr];
                }
            }
            
            if (start >= 0 && end < array.count) {
                // 区间值
                for (long index = start; index <= end; index++){
                    MemModel *model = array[index];
                    [marr addObject:model];
                }
            }
            
            // 尾数值
            NSMutableArray *tmp = array.mutableCopy;
            [tmp removeObjectsInArray:marr];
            for (MemModel *model in tmp) {
                for (NSString *subStr in ma) {
                    if ([[model.address uppercaseString] hasSuffix:[subStr uppercaseString]]) {
                        [marr addObject:model];
                    }
                }
            }
        }
        else{
            NSArray *arr = [indexs componentsSeparatedByString:@","];
            for (NSInteger i = 0; i < arr.count; i++) {
                NSInteger idx = [arr[i] integerValue] - 1;
                if (idx < array.count) {
                    [marr addObject:array[idx]];
                }
            }
        }
    }
    
    // 进行修改
    for (MemModel *model in marr) {
        model.value = value;
        //NSLog(@"memlog: 修改 address: %@ / value: %@ / type: %lu", model.address, model.value, (unsigned long)model.type);
        [[VMTool share] modifyValue:model.value address:model.address type:model.type];
        
        if (open) {
            MemModel *clone = [model clone];
            clone.selected = YES;
            [[NSNotificationCenter defaultCenter] postNotificationName:@"kSaveRecordNotification" object:clone];
        }
    }
}

- (void)oneKeySetup:(NSArray *)array
{
    if (array.count == 0) {
        return;
    }

    _modifying = YES;
    [self oneKeySetup:array index:0];
}

- (void)oneKeySetup:(NSArray *)array index:(NSInteger)index
{
    if (index >= array.count) {

        _currentResult = nil;

        // 通知修改完成
        [[NSNotificationCenter defaultCenter] postNotificationName:@"kVMMdFinish" object:nil];
        return;
    }

    VMOneKeySubModel *model = array[index];

    switch (model.type) {
        case VMOneKeySubType_NumberSearch:{

            // 数值
            NSString *text = model.value;
            VMMemValueType type = [[self keyValues][model.key] unsignedIntValue];
            VMMemComparison comp = VMMemComparisonEQ;

            [[VMTool share] searchValue:text type:type comparison:comp callback:^(NSInteger count, NSArray * _Nonnull result) {
                
                if (result.count == 0) {
                    // 数值搜索没结果通知下去,继续执行别的任务
                    [[NSNotificationCenter defaultCenter] postNotificationName:@"kVMMdFinish" object:nil];
                    
                    [self oneKeySetup:array index:index+1];
                    return;
                }
                
                if (result.count) {
                    [self oneKeySetup:array index:index+1];
                }
            }];
        }
            break;
        case VMOneKeySubType_NearRange:{

            // 邻近范围
            [self setRange:model.value];

            [self oneKeySetup:array index:index+1];
        }
            break;
        case VMOneKeySubType_NearSearch:{

            // 邻近搜索
            NSArray *subArray = [model.value componentsSeparatedByString:@","];
            VMMemValueType type = [[self keyValues][model.key] unsignedIntValue];
            int range = [self rangeValue];
            VMMemComparison comp = VMMemComparisonEQ;

            [self repeatNearSearch:array index:index subArray:subArray range:range type:type subIndex:0 comparison:comp];
        }
            break;
        case VMOneKeySubType_Result:{

            // 修改结果
            [self modifyWithArray:_currentResult value:model.value indexs:model.indexs open:model.switOpen];

            [self oneKeySetup:array index:index+1];
        }
            break;
        case VMOneKeySubType_Clear:{
            
            if (model.clearOpen) {
                //NSLog(@"memlog: 清除结果,执行任务");
                [[VMTool share] reset];
            }
            
            [self oneKeySetup:array index:index+1];
        }
            break;
        default:
            break;
    }
}

- (void)repeatNearSearch:(NSArray *)array index:(NSInteger)index subArray:(NSArray *)subArray range:(int)range type:(VMMemValueType)type subIndex:(NSInteger)subIndex comparison:(VMMemComparison)comparison
{
    NSString *val = subArray[subIndex];
    NSInteger top = subArray.count;
    
    __weak typeof(self) ws = self;
    [[VMTool share] nearMemSearch:val type:type range:range callback:^(NSInteger count, NSArray * _Nonnull result) {
        
        __strong typeof(ws) ss = ws;
        
        if (result.count == 0) {
            // 通知修改完成,邻近搜索没结果通知下去,继续执行别的任务
            [[NSNotificationCenter defaultCenter] postNotificationName:@"kVMMdFinish" object:nil];
            
            [self oneKeySetup:array index:index+1];
            return;
        }
        
        NSInteger idx = subIndex + 1;
        //NSLog(@"idx:%@",@(idx));
        
        // 全部搜索完成
        if (idx == top) {
            if (result.count) {
                [ss oneKeySetup:array index:index+1];
            }
        }
        else{
            // 继续下一次搜索
            [ss repeatNearSearch:array index:index subArray:subArray range:range type:type subIndex:idx comparison:comparison];
        }
    }];
}

#pragma mark - private

// 邻近近搜索
- (void)_nearMemSearch:(const char*)value type:(int)type range:(int)range callback:(nonnull VMToolSearchBlock)block{
    int size = 0;
    void *v = value_of_type(value, type, &size);
    __block int count = 0;
    
    __weak typeof(self) ws = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __strong typeof(ws) ss = ws;
        ss->g_chain = near_mem_search_func(ss->g_task, v, size, type, ss->g_chain, &count, range);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self updateChainArray:ss->g_chain count:count callback:block];
        });
    });
}

// 数值搜索
- (void)_searchMem:(const char *)value type:(int)type comparison:(int)comparison callback:(nonnull VMToolSearchBlock)block {
    int size = 0;
    void *v = value_of_type(value, type, &size);
    __block int count = 0;
    
    __weak typeof(self) ws = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __strong typeof(ws) ss = ws;
        ss->g_chain = search_mem(ss->g_task, v, size, type, comparison, ss->g_chain, &count);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self updateChainArray:ss->g_chain count:count callback:block];
        });
    });
}

// 修改数值
- (void)_modifyMem:(mach_vm_address_t)address value:(const char *)value type:(int)type
{
    int size = 0;
    void *v = value_of_type(value, type, &size);
    
    int ret = write_mem(g_task, address, v, size);
    if (ret == 1) {
        NSLog(@"memlog: 修改成功");
    }
    else {
        NSLog(@"memlog: 修改失败: %d", ret);
    }
}

static long get_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

- (void)updateChainArray:(search_result_chain_t)chain count:(int)count callback:(nonnull VMToolSearchBlock)block
{
    long begin_time = get_timestamp();
    NSLog(@"memlog: 结果数量: %@",@(count));
    
    static NSUInteger max_thread_count = 50;
    __block dispatch_semaphore_t thread_semaphore = dispatch_semaphore_create(max_thread_count);
    
    _chainCount = count;
    
    NSMutableArray *marr = @[].mutableCopy;
    
    if (count > 0 && count <= MaxResultCount) {
        search_result_chain_t c = chain;
        
        int i = 0;
        while (i < count) {
            if (c->result) {
                dispatch_semaphore_wait(thread_semaphore, DISPATCH_TIME_FOREVER);
                
                MemModel *model = [[MemModel alloc] init];
#if 1
                model.o_addr = c->result->address;
#else
                model.address = [NSString stringWithFormat:@"0x%llX", c->result->address];
#endif
                model.value = [self valueStringFromResult:c->result];
                model.type = _type;
                
                if (_searchType == 0) [marr addObject:model];
                if (_searchType == 1) if (![marr containsObject:model]) [marr addObject:model];
                dispatch_semaphore_signal(thread_semaphore);
            }
            
            c = c->next;
            if (c == NULL) break;
        }
    }
    
    for (int index = 0; index < max_thread_count; index++) {
        dispatch_semaphore_wait(thread_semaphore, DISPATCH_TIME_FOREVER);
    }
    for (int index = 0; index < max_thread_count; index++) {
        dispatch_semaphore_signal(thread_semaphore);
    }
    
    NSLog(@"memlog: 模型转换耗时: %.3f(s)",(float)(get_timestamp() - begin_time)/1000.0f);
    
    _currentResult = marr;
    
    // 排序
    [marr sortUsingComparator:^NSComparisonResult(MemModel *obj1, MemModel *obj2) {
        return [obj1.address compare:obj2.address];
    }];
    
    if (block) {
        block(count, marr);
    }
    
}

#pragma mark - Utils
- (int)memTypeFromVMMemValueType:(VMMemValueType)type {
    switch (type) {
        case VMMemValueTypeUnsignedByte: return SearchResultValueTypeUInt8;
        case VMMemValueTypeSignedByte: return SearchResultValueTypeSInt8;
        case VMMemValueTypeUnsignedShort: return SearchResultValueTypeUInt16;
        case VMMemValueTypeSignedShort: return SearchResultValueTypeSInt16;
        case VMMemValueTypeUnsignedInt: return SearchResultValueTypeUInt32;
        case VMMemValueTypeSignedInt: return SearchResultValueTypeSInt32;
        case VMMemValueTypeUnsignedLong: return SearchResultValueTypeUInt64;
        case VMMemValueTypeSignedLong: return SearchResultValueTypeSInt64;
        case VMMemValueTypeFloat: return SearchResultValueTypeFloat;
        case VMMemValueTypeDouble: return SearchResultValueTypeDouble;
        default: return SearchResultValueTypeUndef;
    }
}

- (int)memComparisonFromVMMemComparison:(VMMemComparison)comparison {
    switch (comparison) {
        case VMMemComparisonLT: return SearchResultComparisonLT;
        case VMMemComparisonLE: return SearchResultComparisonLE;
        case VMMemComparisonEQ: return SearchResultComparisonEQ;
        case VMMemComparisonGE: return SearchResultComparisonGE;
        case VMMemComparisonGT: return SearchResultComparisonGT;
        default: return SearchResultComparisonEQ;
    }
}

#pragma mark - Utils
- (NSString *)valueStringFromResult:(search_result_t)result {
    NSString *value = nil;
    int type = result->type;
    ////Modify by innovator
    if (type == SearchResultValueTypeUInt8) {
        uint8_t v = (result->value.uint8Value);
        value = [NSString stringWithFormat:@"%u", v];
    } else if (type == SearchResultValueTypeSInt8) {
        int8_t v = (result->value.sint8Value);
        value = [NSString stringWithFormat:@"%d", v];
    } else if (type == SearchResultValueTypeUInt16) {
        uint16_t v = (result->value.uint16Value);
        value = [NSString stringWithFormat:@"%u", v];
    } else if (type == SearchResultValueTypeSInt16) {
        int16_t v = (result->value.sint16Value);
        value = [NSString stringWithFormat:@"%d", v];
    } else if (type == SearchResultValueTypeUInt32) {
        uint32_t v = (result->value.uint32Value);
        value = [NSString stringWithFormat:@"%u", v];
    } else if (type == SearchResultValueTypeSInt32) {
        int32_t v = (result->value.sint32Value);
        value = [NSString stringWithFormat:@"%d", v];
    } else if (type == SearchResultValueTypeUInt64) {
        uint64_t v = (result->value.uint64Value);
        value = [NSString stringWithFormat:@"%llu", v];
    } else if (type == SearchResultValueTypeSInt64) {
        int64_t v = (result->value.sint64Value);
        value = [NSString stringWithFormat:@"%lld", v];
    } else if (type == SearchResultValueTypeFloat) {
        float v = (result->value.floatValue);
        value = [NSString stringWithFormat:@"%.7g", v]; // %.7g
    } else if (type == SearchResultValueTypeDouble) {
        double v = (result->value.doubleValue);
        value = [NSString stringWithFormat:@"%.15le", v]; // %.15le
    } else {
        NSMutableString *ms = [NSMutableString string];
        char *v = (char *)(result->value.charValue);
        for (int i = 0; i < result->size; ++i) {
            printf("%02X ", v[i]);
            [ms appendFormat:@"%02X ", v[i]];
        }
        value = ms;
    }
    return value;
}

//- (NSString *)valueStringFromResult:(search_result_t)result {
//    NSString *value = nil;
//    int type = result->type;
//    if (type == SearchResultValueTypeUInt8) {
//        uint8_t v = *(uint8_t *)(result->value);
//        value = [NSString stringWithFormat:@"%u", v];
//    } else if (type == SearchResultValueTypeSInt8) {
//        int8_t v = *(int8_t *)(result->value);
//        value = [NSString stringWithFormat:@"%d", v];
//    } else if (type == SearchResultValueTypeUInt16) {
//        uint16_t v = *(uint16_t *)(result->value);
//        value = [NSString stringWithFormat:@"%u", v];
//    } else if (type == SearchResultValueTypeSInt16) {
//        int16_t v = *(int16_t *)(result->value);
//        value = [NSString stringWithFormat:@"%d", v];
//    } else if (type == SearchResultValueTypeUInt32) {
//        uint32_t v = *(uint32_t *)(result->value);
//        value = [NSString stringWithFormat:@"%u", v];
//    } else if (type == SearchResultValueTypeSInt32) {
//        int32_t v = *(int32_t *)(result->value);
//        value = [NSString stringWithFormat:@"%d", v];
//    } else if (type == SearchResultValueTypeUInt64) {
//        uint64_t v = *(uint64_t *)(result->value);
//        value = [NSString stringWithFormat:@"%llu", v];
//    } else if (type == SearchResultValueTypeSInt64) {
//        int64_t v = *(int64_t *)(result->value);
//        value = [NSString stringWithFormat:@"%lld", v];
//    } else if (type == SearchResultValueTypeFloat) {
//        float v = *(float *)(result->value);
//        value = [NSString stringWithFormat:@"%.7g", v]; // %.7g
//    } else if (type == SearchResultValueTypeDouble) {
//        double v = *(double *)(result->value);
//        value = [NSString stringWithFormat:@"%.15le", v]; // %.15le
//    } else {
//        NSMutableString *ms = [NSMutableString string];
//        char *v = (char *)(result->value);
//        for (int i = 0; i < result->size; ++i) {
//            printf("%02X ", v[i]);
//            [ms appendFormat:@"%02X ", v[i]];
//        }
//        value = ms;
//    }
//    return value;
//}

@end

