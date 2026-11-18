// heap.m: placement heaps (MTLHeapTypePlacement) and shared-storage heaps on the HD 4000 (diag#0019).
//
// MetalOld's -[MTLHeapDescriptorInternal validateWithDevice:] aborts on a placement heap ("Placement heap type is not
// supported."), and the HD 4000 driver's MTLIGAccelHeap has no placement path. RealityKit asks for one unconditionally:
// CoreRE re::RenderGraphResourceAllocationManager::allocateNewHeap -> MetalPlacementHeap::init (Private, type 1) when
// usePlacementHeaps() (defaults key, true by default), so every RealityKit engine (Quick Look of .usdz, RealityView)
// aborted at engine init.
//
// A placement heap is emulated by an object that answers MTLHeap and makes each resource the client places at an offset
// as an ordinary device resource with the heap's storage and CPU cache modes (hazard tracking left to MetalOld). Aliasing
// is kept where it matters for memory: the heap holds the resources it made, keyed by byte range; asking again at the
// same offset with the same descriptor returns the same object (the same memory, as on real hardware), and placing a
// resource over a range drops the heap's hold on every resource it overlaps. The heap's own holds therefore never exceed
// its size. Contents of aliased resources are undefined in Metal, so not sharing memory between different resources is
// within the contract.
//
// Shared-storage automatic heaps the same way (RealityKit's re::HeapPool::allocateNewHeap, from
// RenderDataGPU<realitykit::AnchorConstants> at RenderContext::init): the HD 4000 answers NO to
// supportsSharedStorageHeapResources and validateWithDevice: aborts ("Shared storage mode disallowed"). The emulated
// automatic heap makes each newBufferWithLength:options: / newTextureWithDescriptor: an ordinary device resource with
// the heap's storage and CPU cache modes, counts the live ones against its size (usedSize, maxAvailableSize, nil when
// full, as a real heap answers), and its useHeap(s) becomes useResources for them.
//
// useHeap(s) on an encoder becomes useResources:usage:Read for the live resources of emulated heaps (MetalOld's compute
// useHeap: is doesNotRecognizeSelector:). AGB_KEEP_PLACEMENT_HEAPS leaves placement heaps to MetalOld (A/B);
// AGB_TRACE_HEAPS=1 logs every placement.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <os/lock.h>

void agb_placement_install(Class device, Class render, Class compute, void (*log)(const char *, ...));

static void (*heap_log)(const char *, ...);
static BOOL g_traceHeaps;

@interface AGBPlacementEntry : NSObject { @public NSUInteger offset, length; NSString *key; id resource; } @end
@implementation AGBPlacementEntry @end

@interface AGBPlacementHeap : NSObject <MTLHeap> {
    @public
    id<MTLDevice> _device;
    NSUInteger _size;
    MTLStorageMode _storage;
    MTLCPUCacheMode _cache;
    MTLHazardTrackingMode _hazard;
    MTLPurgeableState _purgeable;
    BOOL _automatic;                              // an emulated shared-storage automatic heap, not a placement heap
    NSMapTable *_sizes;                           // automatic: live resource (weak) -> its heap size
    NSMutableArray<AGBPlacementEntry *> *_held;   // non-overlapping byte ranges
    NSHashTable *_live;                           // every resource made and still alive (weak)
    os_unfair_lock _lock;
}
@property (copy, atomic) NSString *label;
@end

static NSString *texKey(MTLTextureDescriptor *t) {
    NSMutableString *k = [NSMutableString stringWithFormat:@"t %lu %lu %lu %lu %lu %lu %lu %lu %lu", (unsigned long)t.textureType,
        (unsigned long)t.pixelFormat, (unsigned long)t.width, (unsigned long)t.height, (unsigned long)t.depth,
        (unsigned long)t.mipmapLevelCount, (unsigned long)t.sampleCount, (unsigned long)t.arrayLength, (unsigned long)t.usage];
    MTLTextureSwizzleChannels s = t.swizzle;
    [k appendFormat:@" %u%u%u%u %d", s.red, s.green, s.blue, s.alpha, (int)t.allowGPUOptimizedContents];
    if (@available(macOS 12.5, *)) if ([t respondsToSelector:@selector(compressionType)]) [k appendFormat:@" c%ld", (long)t.compressionType];
    return k;
}

@implementation AGBPlacementHeap
- (instancetype)initWithDevice:(id<MTLDevice>)d descriptor:(MTLHeapDescriptor *)hd {
    if (!(self = [super init])) return nil;
    _device = d; _size = hd.size; _storage = hd.storageMode; _cache = hd.cpuCacheMode;
    _hazard = [hd respondsToSelector:@selector(hazardTrackingMode)] ? hd.hazardTrackingMode : MTLHazardTrackingModeDefault;
    _automatic = hd.type == MTLHeapTypeAutomatic;
    if (_hazard == MTLHazardTrackingModeDefault)   // the defaults: placement heaps untracked, automatic heaps tracked
        _hazard = _automatic ? MTLHazardTrackingModeTracked : MTLHazardTrackingModeUntracked;
    _sizes = [NSMapTable weakToStrongObjectsMapTable];
    _purgeable = MTLPurgeableStateNonVolatile;
    _held = [NSMutableArray new]; _live = [NSHashTable weakObjectsHashTable]; _lock = OS_UNFAIR_LOCK_INIT;
    return self;
}
- (id<MTLDevice>)device { return _device; }
- (MTLHeapType)type { return _automatic ? MTLHeapTypeAutomatic : MTLHeapTypePlacement; }
- (MTLStorageMode)storageMode { return _storage; }
- (MTLCPUCacheMode)cpuCacheMode { return _cache; }
- (MTLHazardTrackingMode)hazardTrackingMode { return _hazard; }
- (MTLResourceOptions)resourceOptions {
    return (MTLResourceOptions)((_cache << MTLResourceCPUCacheModeShift) | (_storage << MTLResourceStorageModeShift) |
                                (_hazard << MTLResourceHazardTrackingModeShift));
}
- (NSUInteger)size { return _size; }
- (NSUInteger)currentAllocatedSize { return _size; }
- (NSUInteger)allocatedSize { return _size; }
- (NSUInteger)usedLocked {
    NSUInteger u = 0;
    // reading a weak key retains and autoreleases it: drain here, or a released resource would outlive its release
    if (_automatic) @autoreleasepool { for (id r in _sizes) u += [[_sizes objectForKey:r] unsignedLongValue]; }
    else for (AGBPlacementEntry *e in _held) u += e->length;
    return u;
}
- (NSUInteger)usedSize { os_unfair_lock_lock(&_lock); NSUInteger u = [self usedLocked]; os_unfair_lock_unlock(&_lock); return u; }
// Placement heaps leave placement to the client: the whole heap is always available. An automatic heap has what its
// live resources leave.
- (NSUInteger)maxAvailableSizeWithAlignment:(NSUInteger)a {
    NSUInteger free_ = _automatic ? _size - MIN(_size, self.usedSize) : _size;
    return a > 1 ? free_ / a * a : free_;
}
- (MTLPurgeableState)setPurgeableState:(MTLPurgeableState)s {
    MTLPurgeableState old = _purgeable; if (s != MTLPurgeableStateKeepCurrent) _purgeable = s; return old;
}
- (MTLResourceOptions)heapOptions:(MTLResourceOptions)o {
    return (o & ~(MTLResourceOptions)((0xF << MTLResourceStorageModeShift) | (0xF << MTLResourceCPUCacheModeShift) |
                                      (0x3 << MTLResourceHazardTrackingModeShift)))
           | (_storage << MTLResourceStorageModeShift) | (_cache << MTLResourceCPUCacheModeShift);
}
// An automatic heap makes a resource when its live ones leave room for it, and answers nil otherwise (as a full heap
// does). No block or autorelease in between: a released resource gives its room back at once, as on real hardware.
- (BOOL)roomLocked:(NSUInteger)length used:(NSUInteger *)used {
    *used = [self usedLocked];
    return length <= _size && *used <= _size - length;
}
- (void)recordLocked:(id)r length:(NSUInteger)length used:(NSUInteger)used what:(const char *)what {
    if (r) { [_sizes setObject:@(length) forKey:r]; [_live addObject:r]; }
    if (g_traceHeaps || !r) heap_log("shared heap %p: %s size %lu used %lu of %lu -> %s %p", self, what, (unsigned long)length,
                                     (unsigned long)used, (unsigned long)_size, r ? "new" : "FULL", r);
}
// Without an offset: an automatic heap's calls, invalid on a placement heap (Metal's validation says so; answer nil).
- (id<MTLBuffer>)newBufferWithLength:(NSUInteger)l options:(MTLResourceOptions)o {
    if (!_automatic) { heap_log("placement heap: newBufferWithLength:options: without offset"); return nil; }
    MTLResourceOptions opts = [self heapOptions:o];
    MTLSizeAndAlign sa = [_device heapBufferSizeAndAlignWithLength:l options:opts];
    NSUInteger length = MAX(sa.size, l), used;
    os_unfair_lock_lock(&_lock);
    id<MTLBuffer> b = [self roomLocked:length used:&used] ? [_device newBufferWithLength:l options:opts] : nil;
    [self recordLocked:b length:length used:used what:"buffer"];
    os_unfair_lock_unlock(&_lock);
    return b;
}
- (id<MTLTexture>)newTextureWithDescriptor:(MTLTextureDescriptor *)desc {
    if (!_automatic) { heap_log("placement heap: newTextureWithDescriptor: without offset"); return nil; }
    MTLTextureDescriptor *td = [desc copy];
    td.storageMode = _storage; td.cpuCacheMode = _cache;
    MTLSizeAndAlign sa = [_device heapTextureSizeAndAlignWithDescriptor:td];
    NSUInteger used;
    os_unfair_lock_lock(&_lock);
    id<MTLTexture> t = [self roomLocked:sa.size used:&used] ? [_device newTextureWithDescriptor:td] : nil;
    [self recordLocked:t length:sa.size used:used what:"texture"];
    os_unfair_lock_unlock(&_lock);
    return t;
}
// The resource the heap holds at exactly (offset, key), or nil after dropping every hold overlapping [offset, offset+length).
- (id)takeAt:(NSUInteger)offset length:(NSUInteger)length key:(NSString *)key {
    for (AGBPlacementEntry *e in _held)
        if (e->offset == offset && e->length == length && [e->key isEqualToString:key]) return e->resource;
    NSIndexSet *gone = [_held indexesOfObjectsPassingTest:^BOOL(AGBPlacementEntry *e, NSUInteger i, BOOL *stop) {
        return e->offset < offset + length && offset < e->offset + e->length; }];
    [_held removeObjectsAtIndexes:gone];
    return nil;
}
- (void)hold:(id)r offset:(NSUInteger)offset length:(NSUInteger)length key:(NSString *)key {
    AGBPlacementEntry *e = [AGBPlacementEntry new]; e->offset = offset; e->length = length; e->key = key; e->resource = r;
    [_held addObject:e]; [_live addObject:r];
}
- (BOOL)fits:(NSUInteger)offset length:(NSUInteger)length what:(const char *)what {
    if (length && offset <= _size && length <= _size - offset) return YES;
    heap_log("placement heap %p: %s at offset %lu length %lu outside size %lu", self, what, (unsigned long)offset,
             (unsigned long)length, (unsigned long)_size);
    return NO;
}
- (id<MTLBuffer>)newBufferWithLength:(NSUInteger)length options:(MTLResourceOptions)o offset:(NSUInteger)offset {
    if (_automatic) { heap_log("shared heap: newBufferWithLength:options:offset: on an automatic heap"); return nil; }
    MTLSizeAndAlign sa = [_device heapBufferSizeAndAlignWithLength:length options:o];
    if (![self fits:offset length:MAX(sa.size, length) what:"buffer"]) return nil;
    MTLResourceOptions opts = [self heapOptions:o];
    NSString *key = [NSString stringWithFormat:@"b %lu %lu", (unsigned long)length, (unsigned long)opts];
    os_unfair_lock_lock(&_lock);
    id<MTLBuffer> b = [self takeAt:offset length:MAX(sa.size, length) key:key];
    BOOL reused = b != nil;
    if (!b && (b = [_device newBufferWithLength:length options:opts])) [self hold:b offset:offset length:MAX(sa.size, length) key:key];
    os_unfair_lock_unlock(&_lock);
    if (g_traceHeaps) heap_log("placement heap %p: buffer offset %lu length %lu -> %s %p", self, (unsigned long)offset,
                               (unsigned long)length, b ? (reused ? "same" : "new") : "FAILED", b);
    return b;
}
- (id<MTLTexture>)newTextureWithDescriptor:(MTLTextureDescriptor *)desc offset:(NSUInteger)offset {
    if (_automatic) { heap_log("shared heap: newTextureWithDescriptor:offset: on an automatic heap"); return nil; }
    MTLTextureDescriptor *td = [desc copy];
    td.storageMode = _storage; td.cpuCacheMode = _cache;
    if ([td respondsToSelector:@selector(setHazardTrackingMode:)]) td.hazardTrackingMode = MTLHazardTrackingModeDefault;
    MTLSizeAndAlign sa = [_device heapTextureSizeAndAlignWithDescriptor:td];
    if (![self fits:offset length:sa.size what:"texture"]) return nil;
    NSString *key = texKey(td);
    os_unfair_lock_lock(&_lock);
    id<MTLTexture> t = [self takeAt:offset length:sa.size key:key];
    BOOL reused = t != nil;
    if (!t && (t = [_device newTextureWithDescriptor:td])) [self hold:t offset:offset length:sa.size key:key];
    os_unfair_lock_unlock(&_lock);
    if (g_traceHeaps) heap_log("placement heap %p: texture %lux%lu format %lu offset %lu size %lu -> %s %p", self,
                               (unsigned long)td.width, (unsigned long)td.height, (unsigned long)td.pixelFormat,
                               (unsigned long)offset, (unsigned long)sa.size, t ? (reused ? "same" : "new") : "FAILED", t);
    return t;
}
- (id<MTLAccelerationStructure>)newAccelerationStructureWithSize:(NSUInteger)s offset:(NSUInteger)o { return nil; }
- (id<MTLAccelerationStructure>)newAccelerationStructureWithDescriptor:(MTLAccelerationStructureDescriptor *)d offset:(NSUInteger)o { return nil; }
- (id<MTLAccelerationStructure>)newAccelerationStructureWithSize:(NSUInteger)s { return nil; }
- (id<MTLAccelerationStructure>)newAccelerationStructureWithDescriptor:(MTLAccelerationStructureDescriptor *)d { return nil; }
- (NSArray *)liveResources { os_unfair_lock_lock(&_lock); NSArray *a = _live.allObjects; os_unfair_lock_unlock(&_lock); return a; }
- (void)doesNotRecognizeSelector:(SEL)s {
    heap_log("placement heap: unanswered selector %s", sel_getName(s));
    [super doesNotRecognizeSelector:s];
}
@end

// ---------------------------------------------------------------------------------------------------- encoders
// Splits heaps into emulated (-> useResources:count:usage:[stages:] with read usage) and real (-> the original).
typedef void (*UseHeapsIMP)(id, SEL, const id __unsafe_unretained *, NSUInteger);
typedef void (*UseHeapsStagesIMP)(id, SEL, const id __unsafe_unretained *, NSUInteger, MTLRenderStages);
static BOOL useEmulated(id enc, const id __unsafe_unretained *heaps, NSUInteger n, BOOL stages, MTLRenderStages st,
                        NSMutableArray *real) {
    BOOL any = NO;
    for (NSUInteger i = 0; i < n; i++) {
        if (![heaps[i] isKindOfClass:AGBPlacementHeap.class]) { if (heaps[i]) [real addObject:heaps[i]]; continue; }
        any = YES;
        NSArray *rs = [(AGBPlacementHeap *)heaps[i] liveResources];
        if (!rs.count) continue;
        id __unsafe_unretained *v = (id __unsafe_unretained *)calloc(rs.count, sizeof(id));
        for (NSUInteger j = 0; j < rs.count; j++) v[j] = rs[j];
        if (stages && [enc respondsToSelector:@selector(useResources:count:usage:stages:)])
            [enc useResources:v count:rs.count usage:MTLResourceUsageRead stages:st];
        else if ([enc respondsToSelector:@selector(useResources:count:usage:)])
            [enc useResources:v count:rs.count usage:MTLResourceUsageRead];
        free(v);
    }
    return any;
}
static void hookUse(Class c, BOOL render) {
    if (!c) return;
    SEL s1 = @selector(useHeap:), sN = @selector(useHeaps:count:);
    SEL s1s = @selector(useHeap:stages:), sNs = @selector(useHeaps:count:stages:);
    Method m;
    if ((m = class_getInstanceMethod(c, sN))) {
        __block UseHeapsIMP o = (UseHeapsIMP)method_getImplementation(m);
        IMP imp = imp_implementationWithBlock(^(id enc, const id __unsafe_unretained *h, NSUInteger n) { @autoreleasepool {
            NSMutableArray *real = [NSMutableArray new];
            if (!useEmulated(enc, h, n, NO, 0, real)) { o(enc, sN, h, n); return; }
            if (!real.count) return;
            id __unsafe_unretained v[real.count]; for (NSUInteger i = 0; i < real.count; i++) v[i] = real[i];
            o(enc, sN, v, real.count);
        }});
        if (!class_addMethod(c, sN, imp, method_getTypeEncoding(m))) method_setImplementation(class_getInstanceMethod(c, sN), imp);
    }
    if ((m = class_getInstanceMethod(c, s1))) {
        __block IMP o = method_getImplementation(m);
        IMP imp = imp_implementationWithBlock(^(id enc, id heap) { @autoreleasepool {
            id __unsafe_unretained h[1] = { heap };
            if (!useEmulated(enc, h, 1, NO, 0, [NSMutableArray new])) ((void (*)(id, SEL, id))o)(enc, s1, heap);
        }});
        if (!class_addMethod(c, s1, imp, method_getTypeEncoding(m))) method_setImplementation(class_getInstanceMethod(c, s1), imp);
    }
    if (!render) return;
    if ((m = class_getInstanceMethod(c, sNs))) {
        __block UseHeapsStagesIMP o = (UseHeapsStagesIMP)method_getImplementation(m);
        IMP imp = imp_implementationWithBlock(^(id enc, const id __unsafe_unretained *h, NSUInteger n, MTLRenderStages st) { @autoreleasepool {
            NSMutableArray *real = [NSMutableArray new];
            if (!useEmulated(enc, h, n, YES, st, real)) { o(enc, sNs, h, n, st); return; }
            if (!real.count) return;
            id __unsafe_unretained v[real.count]; for (NSUInteger i = 0; i < real.count; i++) v[i] = real[i];
            o(enc, sNs, v, real.count, st);
        }});
        if (!class_addMethod(c, sNs, imp, method_getTypeEncoding(m))) method_setImplementation(class_getInstanceMethod(c, sNs), imp);
    }
    if ((m = class_getInstanceMethod(c, s1s))) {
        __block IMP o = method_getImplementation(m);
        IMP imp = imp_implementationWithBlock(^(id enc, id heap, MTLRenderStages st) { @autoreleasepool {
            id __unsafe_unretained h[1] = { heap };
            if (!useEmulated(enc, h, 1, YES, st, [NSMutableArray new])) ((void (*)(id, SEL, id, MTLRenderStages))o)(enc, s1s, heap, st);
        }});
        if (!class_addMethod(c, s1s, imp, method_getTypeEncoding(m))) method_setImplementation(class_getInstanceMethod(c, s1s), imp);
    }
}

// ---------------------------------------------------------------------------------------------------- install
// MetalOld's validateWithDevice: asks the device the same; a device that doesn't answer keeps the driver's path.
static BOOL deviceHasSharedHeaps(id d) {
    SEL q = sel_registerName("supportsSharedStorageHeapResources");
    return ![d respondsToSelector:q] || ((BOOL (*)(id, SEL))objc_msgSend)(d, q);
}
typedef id (*NewHeapIMP)(id, SEL, MTLHeapDescriptor *) __attribute__((ns_returns_retained));
void agb_placement_install(Class device, Class render, Class compute, void (*log)(const char *, ...)) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        heap_log = log;
        if (getenv("AGB_KEEP_PLACEMENT_HEAPS")) { log("placement heaps left to MetalOld (AGB_KEEP_PLACEMENT_HEAPS)"); return; }
        const char *t = getenv("AGB_TRACE_HEAPS"); g_traceHeaps = t && *t && *t != '0';
        SEL s = @selector(newHeapWithDescriptor:);
        Method m = class_getInstanceMethod(device, s);
        if (!m) { log("%s lacks newHeapWithDescriptor:", class_getName(device)); return; }
        __block NewHeapIMP o = (NewHeapIMP)method_getImplementation(m);
        IMP imp = imp_implementationWithBlock(^id(id d, MTLHeapDescriptor *hd) __attribute__((ns_returns_retained)) {
            BOOL shared = hd.type == MTLHeapTypeAutomatic && hd.storageMode == MTLStorageModeShared && !deviceHasSharedHeaps(d);
            if (hd.type != MTLHeapTypePlacement && !shared) return o(d, s, hd);
            AGBPlacementHeap *h = [[AGBPlacementHeap alloc] initWithDevice:d descriptor:hd];
            log("%s heap %p emulated: size %lu storage %lu cache %lu hazard %lu", shared ? "shared" : "placement", h,
                (unsigned long)hd.size, (unsigned long)hd.storageMode, (unsigned long)hd.cpuCacheMode, (unsigned long)h->_hazard);
            return h;
        });
        if (!class_addMethod(device, s, imp, method_getTypeEncoding(m))) method_setImplementation(class_getInstanceMethod(device, s), imp);
        hookUse(render, YES);
        hookUse(compute, NO);
    });
}
