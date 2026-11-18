// Host probe for libargbuf's shared-storage heap emulation (diag#0019), CoreRE's re::HeapPool pattern: an automatic
// heap with Shared storage, newBufferWithLength:options: until it is full, CPU writes, useHeap: on a compute encoder and
// a dispatch through a heap buffer. With "nosharedheaps" the device's supportsSharedStorageHeapResources answers NO
// first (the HD 4000's answer, so the host takes the laptop's path). Prints "name value" lines.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <objc/runtime.h>
static void logf_(const char *fmt, ...) { va_list a; va_start(a, fmt); vfprintf(stderr, fmt, a); va_end(a); fputc('\n', stderr); }
#define P(name, fmt, ...) printf("%s " fmt "\n", name, ##__VA_ARGS__)
static BOOL no(id s, SEL c) { return NO; }
int main(int argc, char **argv) { @autoreleasepool {
    id<MTLDevice> d = MTLCreateSystemDefaultDevice(); id<MTLCommandQueue> q = [d newCommandQueue];
    SEL ss = sel_registerName("supportsSharedStorageHeapResources");
    if (argc > 1 && !strcmp(argv[1], "nosharedheaps"))
        class_replaceMethod([(id)d class], ss, (IMP)no, "c16@0:8");
    P("device_shared_heaps", "%s", [(id)d respondsToSelector:ss] && ((BOOL (*)(id, SEL))objc_msgSend)(d, ss) ? "yes" : "no");
    id<MTLCommandBuffer> c0 = [q commandBuffer]; id<MTLComputeCommandEncoder> ce = [c0 computeCommandEncoder]; Class cc = [(id)ce class]; [ce endEncoding];
    MTLRenderPassDescriptor *rp0 = [MTLRenderPassDescriptor new];
    MTLTextureDescriptor *t0 = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:4 height:4 mipmapped:NO];
    t0.usage = MTLTextureUsageRenderTarget; t0.storageMode = MTLStorageModePrivate; rp0.colorAttachments[0].texture = [d newTextureWithDescriptor:t0];
    id<MTLRenderCommandEncoder> re0 = [c0 renderCommandEncoderWithDescriptor:rp0]; Class rc = [(id)re0 class]; [re0 endEncoding];
    void (*install)(Class, Class, Class, void (*)(const char *, ...)) = dlsym(RTLD_DEFAULT, "agb_placement_install");
    P("libargbuf", "%s", install ? "loaded" : "absent");
    if (install) install([(id)d class], rc, cc, logf_);

    // a Private automatic heap still goes to the driver
    MTLHeapDescriptor *pd = [MTLHeapDescriptor new]; pd.size = 1 << 20; pd.storageMode = MTLStorageModePrivate;
    id<MTLHeap> ph = [d newHeapWithDescriptor:pd];
    P("private_passthrough", "%s", ph && ![NSStringFromClass([(id)ph class]) hasPrefix:@"AGB"] ? "yes" : "no");

    // re::HeapPool::allocateNewHeap: Shared, automatic
    const NSUInteger SZ = 1 << 20;
    MTLHeapDescriptor *hd = [MTLHeapDescriptor new]; hd.size = SZ; hd.storageMode = MTLStorageModeShared; hd.cpuCacheMode = MTLCPUCacheModeDefaultCache;
    id<MTLHeap> h = [d newHeapWithDescriptor:hd];
    P("shared_class", "%s", h ? NSStringFromClass([(id)h class]).UTF8String : "nil");
    P("shared_type", "%ld", (long)h.type);
    P("shared_storage", "%lu", (unsigned long)h.storageMode);
    P("shared_hazard", "%lu", (unsigned long)h.hazardTrackingMode);
    P("empty_available", "%s", [h maxAvailableSizeWithAlignment:256] >= SZ / 2 ? "ok" : "bad");
    // re::HeapPool::allocBuffer
    id<MTLBuffer> b = [h newBufferWithLength:4096 options:MTLResourceStorageModeShared];
    P("buffer_made", "%s", b && b.storageMode == MTLStorageModeShared && b.contents ? "yes" : "no");
    P("used_size", "%s", h.usedSize >= 4096 && h.usedSize <= SZ ? "ok" : "bad");
    NSMutableArray *keep = [NSMutableArray new]; NSUInteger n = 0;
    for (; n < 4096; n++) { id<MTLBuffer> x = [h newBufferWithLength:64 << 10 options:MTLResourceStorageModeShared]; if (!x) break; [keep addObject:x]; }
    P("fills_then_nil", "%s", n > 0 && n < 4096 && h.usedSize <= SZ ? "yes" : "no");
    NSUInteger full = h.usedSize; [keep removeAllObjects];
    @autoreleasepool { id<MTLBuffer> y = [h newBufferWithLength:64 << 10 options:MTLResourceStorageModeShared]; P("freed_reused", "%s", y && h.usedSize < full ? "yes" : "no"); }
    MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:16 height:16 mipmapped:NO];
    td.storageMode = MTLStorageModeShared; td.usage = MTLTextureUsageShaderRead;
    id<MTLTexture> t = [h newTextureWithDescriptor:td];
    P("texture_made", "%s", t && t.storageMode == MTLStorageModeShared ? "yes" : "no");

    // CPU writes, useHeap: on a compute encoder, a dispatch reads and doubles the heap buffer
    for (int i = 0; i < 1024; i++) ((float *)b.contents)[i] = i;
    NSError *e = nil;
    id<MTLLibrary> lib = [d newLibraryWithSource:@"#include <metal_stdlib>\nusing namespace metal;\n"
        "kernel void k(device float *v [[buffer(0)]], uint i [[thread_position_in_grid]]) { v[i] = v[i] * 2; }\n" options:nil error:&e];
    if (!lib) { printf("library failed: %s\n", e.localizedDescription.UTF8String); return 1; }
    id<MTLComputePipelineState> cs = [d newComputePipelineStateWithFunction:[lib newFunctionWithName:@"k"] error:&e];
    id<MTLCommandBuffer> cb = [q commandBuffer];
    id<MTLComputeCommandEncoder> ke = [cb computeCommandEncoder];
    [ke setComputePipelineState:cs]; [ke useHeap:h]; [ke setBuffer:b offset:0 atIndex:0];
    [ke dispatchThreads:MTLSizeMake(1024, 1, 1) threadsPerThreadgroup:MTLSizeMake(64, 1, 1)];
    [ke endEncoding]; [cb commit]; [cb waitUntilCompleted];
    int ok = 0; for (int i = 0; i < 1024; i++) ok += ((float *)b.contents)[i] == 2.0f * i;
    P("compute_doubled", "%d/1024", ok);
    P("command_status", "%ld", (long)cb.status);
    return 0;
}}
