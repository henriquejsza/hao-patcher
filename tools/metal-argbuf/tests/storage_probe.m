// Host probe for libargbuf's render-target storage rule (src/device/argbuf.m, agb_private_target). Prints one line per
// case: NAME yes|no. Built and run by test_device_storage.py (x86_64, Rosetta).
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
BOOL agb_private_target(MTLTextureDescriptor *td);
MTLPixelFormat agb_packed_depth_stencil(MTLPixelFormat depth, MTLPixelFormat stencil);
BOOL agb_pass_contents_local(MTLRenderPassDescriptor *rp);
static void pk(const char *n, MTLPixelFormat d, MTLPixelFormat st) { printf("%s %lu\n", n, (unsigned long)agb_packed_depth_stencil(d, st)); }
static void pass(const char *n, MTLLoadAction dl, MTLStoreAction ds, MTLLoadAction sl, MTLStoreAction ss) {
    MTLRenderPassDescriptor *r = [MTLRenderPassDescriptor renderPassDescriptor];
    r.depthAttachment.loadAction = dl; r.depthAttachment.storeAction = ds; r.stencilAttachment.loadAction = sl; r.stencilAttachment.storeAction = ss;
    printf("%s %s\n", n, agb_pass_contents_local(r) ? "yes" : "no"); }
static void cu(const char *n, MTLPixelFormat f, MTLTextureType t, NSUInteger s, MTLStorageMode m, MTLTextureUsage u) {
    MTLTextureDescriptor *d = [MTLTextureDescriptor new]; d.pixelFormat = f; d.width = d.height = 512; d.textureType = t;
    d.sampleCount = s; d.usage = u; d.storageMode = m;
    printf("%s %s\n", n, agb_private_target(d) ? "yes" : "no"); }
static void c(const char *n, MTLPixelFormat f, MTLTextureType t, NSUInteger s, MTLStorageMode m) {
    cu(n, f, t, s, m, MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead); }
int main(void) { @autoreleasepool {
    c("weather_msaa_stencil_managed", MTLPixelFormatStencil8, MTLTextureType2DMultisample, 4, MTLStorageModeManaged);
    c("msaa_stencil_memoryless", MTLPixelFormatStencil8, MTLTextureType2DMultisample, 4, MTLStorageModeMemoryless);
    c("msaa_color_shared", MTLPixelFormatBGRA8Unorm, MTLTextureType2DMultisample, 4, MTLStorageModeShared);
    c("depth32_managed", MTLPixelFormatDepth32Float, MTLTextureType2D, 1, MTLStorageModeManaged);
    c("depth24s8_shared", MTLPixelFormatDepth24Unorm_Stencil8, MTLTextureType2D, 1, MTLStorageModeShared);
    c("msaa_stencil_private", MTLPixelFormatStencil8, MTLTextureType2DMultisample, 4, MTLStorageModePrivate);
    c("color_managed", MTLPixelFormatRGBA8Unorm, MTLTextureType2D, 1, MTLStorageModeManaged);
    c("r8_shared", MTLPixelFormatR8Unorm, MTLTextureType2D, 1, MTLStorageModeShared);
    cu("depth32_managed_not_target", MTLPixelFormatDepth32Float, MTLTextureType2D, 1, MTLStorageModeManaged, MTLTextureUsageShaderRead);
    cu("stencil8_shared_not_target", MTLPixelFormatStencil8, MTLTextureType2D, 1, MTLStorageModeShared, MTLTextureUsageShaderRead);
    c("color_memoryless", MTLPixelFormatBGRA8Unorm, MTLTextureType2D, 1, MTLStorageModeMemoryless);
    pk("packed_weather", MTLPixelFormatDepth32Float, MTLPixelFormatStencil8);
    pk("packed_same", MTLPixelFormatDepth32Float_Stencil8, MTLPixelFormatDepth32Float_Stencil8);
    pk("packed_depth_only", MTLPixelFormatDepth32Float, MTLPixelFormatInvalid);
    pk("packed_depth16_stencil8", MTLPixelFormatDepth16Unorm, MTLPixelFormatStencil8);
    pass("pass_clear_dontcare", MTLLoadActionClear, MTLStoreActionDontCare, MTLLoadActionClear, MTLStoreActionDontCare);
    pass("pass_dontcare_dontcare", MTLLoadActionDontCare, MTLStoreActionDontCare, MTLLoadActionDontCare, MTLStoreActionDontCare);
    pass("pass_depth_load", MTLLoadActionLoad, MTLStoreActionDontCare, MTLLoadActionClear, MTLStoreActionDontCare);
    pass("pass_stencil_store", MTLLoadActionClear, MTLStoreActionDontCare, MTLLoadActionClear, MTLStoreActionStore);
    pass("pass_depth_resolve", MTLLoadActionClear, MTLStoreActionMultisampleResolve, MTLLoadActionClear, MTLStoreActionDontCare); }
    return 0; }
