// Host probe for libargbuf's CPU-written MSAA stencil emulation (diag#0002), Weather's exact pattern: a 4x MSAA Stencil8
// 512x512 render target asked for as Managed, a full-region CPU upload of a mask, then an overlay pass with a SEPARATE
// Depth32Float depth texture that loads that stencil and draws red where stencil == 1. The adaptations are installed on
// the host GPU's classes (agb_legacy_install). Prints: blocks_ok N/64, getbytes_ok yes|no, storage S.
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
void agb_legacy_install(Class dev, Class cb, Class tex);
int main(void) { @autoreleasepool {
    id<MTLDevice> d = MTLCreateSystemDefaultDevice(); id<MTLCommandQueue> q = [d newCommandQueue];
    MTLTextureDescriptor *probe = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:4 height:4 mipmapped:NO];
    agb_legacy_install([(id)d class], [(id)[q commandBuffer] class], [(id)[d newTextureWithDescriptor:probe] class]);
    const NSUInteger W = 512;
    MTLTextureDescriptor *sd = [MTLTextureDescriptor new]; sd.textureType = MTLTextureType2DMultisample; sd.pixelFormat = MTLPixelFormatStencil8;
    sd.width = sd.height = W; sd.sampleCount = 4; sd.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead; sd.storageMode = MTLStorageModeManaged;
    id<MTLTexture> stencil = [d newTextureWithDescriptor:sd];
    uint8_t *mask = calloc(W * W, 1); for (NSUInteger y = 0; y < W; y++) for (NSUInteger x = 0; x < W; x++) mask[y * W + x] = ((x / 64 + y / 64) & 1) ? 1 : 0;
    [stencil replaceRegion:MTLRegionMake2D(0, 0, W, W) mipmapLevel:0 withBytes:mask bytesPerRow:W];
    uint8_t *back = calloc(W * W, 1);
    [stencil getBytes:back bytesPerRow:W bytesPerImage:W * W fromRegion:MTLRegionMake2D(0, 0, W, W) mipmapLevel:0 slice:0];
    MTLTextureDescriptor *dd = [sd copy]; dd.pixelFormat = MTLPixelFormatDepth32Float; dd.storageMode = MTLStorageModePrivate; dd.usage = MTLTextureUsageRenderTarget;
    id<MTLTexture> depth = [d newTextureWithDescriptor:dd];
    MTLTextureDescriptor *cd = [sd copy]; cd.pixelFormat = MTLPixelFormatRGBA8Unorm; cd.storageMode = MTLStorageModePrivate; cd.usage = MTLTextureUsageRenderTarget;
    id<MTLTexture> color = [d newTextureWithDescriptor:cd];
    MTLTextureDescriptor *rd = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:W height:W mipmapped:NO];
    rd.usage = MTLTextureUsageRenderTarget; rd.storageMode = MTLStorageModeShared; id<MTLTexture> resolve = [d newTextureWithDescriptor:rd];
    NSError *e = nil;
    id<MTLLibrary> lib = [d newLibraryWithSource:@"#include <metal_stdlib>\nusing namespace metal;\nstruct V { float4 p [[position]]; };\n"
        "vertex V vs(uint i [[vertex_id]]) { float2 q[3] = { float2(-1,-1), float2(3,-1), float2(-1,3) }; V o; o.p = float4(q[i], 0, 1); return o; }\n"
        "fragment float4 fs() { return float4(1, 0, 0, 1); }\n" options:nil error:&e];
    MTLRenderPipelineDescriptor *pd = [MTLRenderPipelineDescriptor new]; pd.vertexFunction = [lib newFunctionWithName:@"vs"]; pd.fragmentFunction = [lib newFunctionWithName:@"fs"];
    pd.colorAttachments[0].pixelFormat = MTLPixelFormatRGBA8Unorm; pd.depthAttachmentPixelFormat = MTLPixelFormatDepth32Float;
    pd.stencilAttachmentPixelFormat = MTLPixelFormatStencil8; pd.rasterSampleCount = 4;
    id<MTLRenderPipelineState> ps = [d newRenderPipelineStateWithDescriptor:pd error:&e];
    if (!ps) { printf("pipeline failed: %s\n", e.localizedDescription.UTF8String); return 1; }
    MTLDepthStencilDescriptor *dsd = [MTLDepthStencilDescriptor new]; dsd.depthCompareFunction = MTLCompareFunctionAlways;
    MTLStencilDescriptor *st = [MTLStencilDescriptor new]; st.stencilCompareFunction = MTLCompareFunctionEqual; st.readMask = 0xFF; st.writeMask = 0;
    dsd.frontFaceStencil = st; dsd.backFaceStencil = st; id<MTLDepthStencilState> dss = [d newDepthStencilStateWithDescriptor:dsd];
    MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
    rp.colorAttachments[0].texture = color; rp.colorAttachments[0].resolveTexture = resolve; rp.colorAttachments[0].loadAction = MTLLoadActionClear;
    rp.colorAttachments[0].clearColor = MTLClearColorMake(0, 0, 0, 1); rp.colorAttachments[0].storeAction = MTLStoreActionMultisampleResolve;
    rp.depthAttachment.texture = depth; rp.depthAttachment.loadAction = MTLLoadActionClear; rp.depthAttachment.storeAction = MTLStoreActionDontCare;
    rp.stencilAttachment.texture = stencil; rp.stencilAttachment.loadAction = MTLLoadActionLoad; rp.stencilAttachment.storeAction = MTLStoreActionDontCare;
    id<MTLCommandBuffer> cb = [q commandBuffer]; id<MTLRenderCommandEncoder> en = [cb renderCommandEncoderWithDescriptor:rp];
    [en setRenderPipelineState:ps]; [en setDepthStencilState:dss]; [en setStencilReferenceValue:1];
    [en drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3]; [en endEncoding]; [cb commit]; [cb waitUntilCompleted];
    if (cb.error) printf("cb error: %s\n", cb.error.localizedDescription.UTF8String);
    uint8_t *px = calloc(W * W * 4, 1); [resolve getBytes:px bytesPerRow:W * 4 fromRegion:MTLRegionMake2D(0, 0, W, W) mipmapLevel:0];
    int ok = 0; for (NSUInteger by = 0; by < 8; by++) for (NSUInteger bx = 0; bx < 8; bx++) {
        NSUInteger x = bx * 64 + 32, y = by * 64 + 32; BOOL red = px[(y * W + x) * 4] > 200; if (red == (mask[y * W + x] == 1)) ok++; }
    printf("blocks_ok %d/64\ngetbytes_ok %s\nstorage %lu\n", ok, memcmp(mask, back, W * W) ? "no" : "yes", (unsigned long)stencil.storageMode); }
    return 0; }
