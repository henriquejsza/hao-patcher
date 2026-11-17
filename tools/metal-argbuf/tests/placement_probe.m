// Host probe for libargbuf's placement-heap emulation (diag#0019), CoreRE's MetalPlacementHeap pattern: a Private
// placement heap (type 1), heapTextureSizeAndAlign + newTextureWithDescriptor:offset:, maxAvailableSizeWithAlignment:,
// usedSize, newBufferWithLength:options:offset:, useHeap:stages: on a render encoder and useHeap: on a compute encoder.
// On the host it is linked against libargbuf and installs the emulation on the host GPU's classes (agb_placement_install);
// built without libargbuf and run on the laptop, the HD 4000 driver has loaded libargbuf already (the call is then a
// no-op, or absent). Prints "name value" lines.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <dlfcn.h>
static void logf_(const char *fmt, ...) { va_list a; va_start(a, fmt); vfprintf(stderr, fmt, a); va_end(a); fputc('\n', stderr); }
#define P(name, fmt, ...) printf("%s " fmt "\n", name, ##__VA_ARGS__)
int main(void) { @autoreleasepool {
    id<MTLDevice> d = MTLCreateSystemDefaultDevice(); id<MTLCommandQueue> q = [d newCommandQueue];
    id<MTLCommandBuffer> c0 = [q commandBuffer]; id<MTLComputeCommandEncoder> ce = [c0 computeCommandEncoder]; Class cc = [(id)ce class]; [ce endEncoding];
    MTLRenderPassDescriptor *rp0 = [MTLRenderPassDescriptor new];
    MTLTextureDescriptor *t0 = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:4 height:4 mipmapped:NO];
    t0.usage = MTLTextureUsageRenderTarget; t0.storageMode = MTLStorageModePrivate; rp0.colorAttachments[0].texture = [d newTextureWithDescriptor:t0];
    id<MTLRenderCommandEncoder> re0 = [c0 renderCommandEncoderWithDescriptor:rp0]; Class rc = [(id)re0 class]; [re0 endEncoding];
    void (*install)(Class, Class, Class, void (*)(const char *, ...)) = dlsym(RTLD_DEFAULT, "agb_placement_install");
    P("libargbuf", "%s", install ? "loaded" : "absent");
    if (install) install([(id)d class], rc, cc, logf_);

    // an automatic heap still goes to the driver
    MTLHeapDescriptor *ad = [MTLHeapDescriptor new]; ad.size = 1 << 20; ad.storageMode = MTLStorageModePrivate;
    id<MTLHeap> auto_ = [d newHeapWithDescriptor:ad];
    P("automatic_passthrough", "%s", auto_ && auto_.type == MTLHeapTypeAutomatic && ![NSStringFromClass([(id)auto_ class]) hasPrefix:@"AGB"] ? "yes" : "no");

    // CoreRE MetalPlacementHeap::init: alloc/init, setStorageMode:2, setSize:, setType:1, newHeapWithDescriptor:
    const NSUInteger SZ = 8 << 20;
    MTLHeapDescriptor *hd = [MTLHeapDescriptor new]; hd.storageMode = MTLStorageModePrivate; hd.size = SZ; hd.type = MTLHeapTypePlacement;
    id<MTLHeap> h = [d newHeapWithDescriptor:hd];
    P("placement_class", "%s", h ? NSStringFromClass([(id)h class]).UTF8String : "nil");
    P("placement_type", "%ld", (long)h.type);
    P("placement_size", "%s", h.size == SZ ? "ok" : "bad");
    P("placement_storage", "%lu", (unsigned long)h.storageMode);
    P("placement_hazard", "%lu", (unsigned long)h.hazardTrackingMode);
    P("max_available", "%s", [h maxAvailableSizeWithAlignment:16] == SZ ? "ok" : "bad");
    P("no_offset_buffer_nil", "%s", [h newBufferWithLength:256 options:MTLResourceStorageModePrivate] == nil ? "yes" : "no");

    // CoreRE MetalPlacementHeap::makeTexture
    const NSUInteger W = 64;
    MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:W height:W mipmapped:NO];
    td.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead; td.storageMode = MTLStorageModePrivate;
    MTLSizeAndAlign sa = [d heapTextureSizeAndAlignWithDescriptor:td];
    id<MTLTexture> a = [h newTextureWithDescriptor:td offset:0];
    id<MTLTexture> a2 = [h newTextureWithDescriptor:td offset:0];
    id<MTLTexture> b = [h newTextureWithDescriptor:td offset:(sa.size + sa.align - 1) / sa.align * sa.align];
    P("texture_made", "%s", a && b ? "yes" : "no");
    P("texture_storage", "%lu", (unsigned long)a.storageMode);
    P("same_offset_same_texture", "%s", a == a2 ? "yes" : "no");
    P("other_offset_other_texture", "%s", a != b ? "yes" : "no");
    P("used_size", "%s", h.usedSize == 2 * sa.size ? "ok" : "bad");
    P("outside_nil", "%s", [h newTextureWithDescriptor:td offset:SZ - 16] == nil ? "yes" : "no");
    // a different descriptor over A's range drops the heap's hold on A, and a new A is made later
    MTLTextureDescriptor *td2 = [td copy]; td2.pixelFormat = MTLPixelFormatR32Float;
    id<MTLTexture> c = [h newTextureWithDescriptor:td2 offset:0];
    id<MTLTexture> a3 = [h newTextureWithDescriptor:td offset:0];
    P("overlap_replaces", "%s", c && c != a && a3 != a && a3 != c ? "yes" : "no");
    P("held_within_size", "%s", h.usedSize <= SZ ? "yes" : "no");

    // draw into a placement texture (render pass clear + useHeap:stages:), copy out with a blit, read back
    id<MTLHeap> sh; { MTLHeapDescriptor *s = [MTLHeapDescriptor new]; s.storageMode = MTLStorageModeShared; s.size = 1 << 20; s.type = MTLHeapTypePlacement; sh = [d newHeapWithDescriptor:s]; }
    id<MTLBuffer> out = [sh newBufferWithLength:W * W * 4 options:MTLResourceStorageModeShared offset:0];
    id<MTLBuffer> in = [sh newBufferWithLength:256 options:MTLResourceStorageModeShared offset:W * W * 4];
    P("buffer_made", "%s", out && in && out.storageMode == MTLStorageModeShared ? "yes" : "no");
    P("buffer_same", "%s", [sh newBufferWithLength:256 options:MTLResourceStorageModeShared offset:W * W * 4] == in ? "yes" : "no");
    for (int i = 0; i < 64; i++) ((float *)in.contents)[i] = i;
    NSError *e = nil;
    id<MTLLibrary> lib = [d newLibraryWithSource:@"#include <metal_stdlib>\nusing namespace metal;\n"
        "struct V { float4 p [[position]]; };\n"
        "vertex V vs(uint i [[vertex_id]]) { float2 q[3] = { float2(-1,-1), float2(3,-1), float2(-1,3) }; V o; o.p = float4(q[i], 0, 1); return o; }\n"
        "fragment float4 fs(constant float *v [[buffer(0)]]) { return float4(v[63] / 63.0, 0, 1, 1); }\n"
        "kernel void k(device float *v [[buffer(0)]], uint i [[thread_position_in_grid]]) { v[i] = v[i] * 2; }\n" options:nil error:&e];
    if (!lib) { printf("library failed: %s\n", e.localizedDescription.UTF8String); return 1; }
    MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new]; pd.vertexFunction = [lib newFunctionWithName:@"vs"];
    pd.fragmentFunction = [lib newFunctionWithName:@"fs"]; pd.colorAttachments[0].pixelFormat = MTLPixelFormatRGBA8Unorm;
    id<MTLRenderPipelineState> ps = [d newRenderPipelineStateWithDescriptor:pd error:&e];
    id<MTLComputePipelineState> cs = [d newComputePipelineStateWithFunction:[lib newFunctionWithName:@"k"] error:&e];
    id<MTLCommandBuffer> cb = [q commandBuffer];
    id<MTLComputeCommandEncoder> ke = [cb computeCommandEncoder];
    [ke useHeap:sh]; [ke setComputePipelineState:cs]; [ke setBuffer:in offset:0 atIndex:0];
    [ke dispatchThreads:MTLSizeMake(64, 1, 1) threadsPerThreadgroup:MTLSizeMake(64, 1, 1)]; [ke endEncoding];
    MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor new]; rp.colorAttachments[0].texture = a3;
    rp.colorAttachments[0].loadAction = MTLLoadActionClear; rp.colorAttachments[0].clearColor = MTLClearColorMake(0, 0, 0, 0);
    rp.colorAttachments[0].storeAction = MTLStoreActionStore;
    id<MTLRenderCommandEncoder> en = [cb renderCommandEncoderWithDescriptor:rp];
    id<MTLHeap> both[2] = { h, sh }; [en useHeaps:both count:2 stages:MTLRenderStageFragment]; [en useHeap:sh stages:MTLRenderStageVertex];
    [en setRenderPipelineState:ps]; [en setFragmentBuffer:in offset:0 atIndex:0];
    [en drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3]; [en endEncoding];
    id<MTLBlitCommandEncoder> bl = [cb blitCommandEncoder];
    [bl copyFromTexture:a3 sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0, 0, 0) sourceSize:MTLSizeMake(W, W, 1)
               toBuffer:out destinationOffset:0 destinationBytesPerRow:W * 4 destinationBytesPerImage:W * W * 4];
    [bl endEncoding]; [cb commit]; [cb waitUntilCompleted];
    if (cb.error) printf("cb_error %s\n", cb.error.localizedDescription.UTF8String);
    const uint8_t *px = out.contents; const float *v = in.contents;
    int good = 0; for (NSUInteger i = 0; i < W * W; i++) good += px[i * 4] == 255 && px[i * 4 + 1] == 0 && px[i * 4 + 2] == 255;
    P("compute_doubled", "%s", v[0] == 0 && v[1] == 2 && v[63] == 126 ? "yes" : "no");
    P("pixels_ok", "%d/%lu", good, (unsigned long)(W * W));
    return 0; } }
