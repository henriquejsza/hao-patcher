// Host model of Weather's precipitation tile upload on the HD 4000 (diag#0055): libargbuf's ASTC hooks on the host GPU's
// classes, a tile made like WeatherMaps' OverlayTexturePool makes it (ASTC_8x8_LDR 512x512, Managed, ShaderRead), and
// WeatherMaps' guard before its upload: replaceRegion only when tile.pixelFormat equals the KTX format (else it drops the
// tile as pixelFormatMismatch). Every block is a void-extent block of one colour (255 64 0 255).
//   R  guard + replaceRegion:mipmapLevel:withBytes:bytesPerRow: (WeatherMaps' path)
//   B  blit copyFromBuffer:...destinationOrigin:options: (WeatherMaps' other upload selector)
// On the laptop (x86_64, image's or swapped libargbuf): astc_tile_probe; before the fix R/B report 70 and upload no.
// Prints: "<case> reported F uploaded yes|no texels N/262144" (N = texels sampled in a compute kernel with the colour).
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>
#include <stdarg.h>
void agb_astc_install(Class device, Class heap, Class blit, void (*log)(const char *, ...));
static void log_line(const char *f, ...) {
    va_list a; va_start(a, f); fprintf(stderr, "astc: "); vfprintf(stderr, f, a); fputc('\n', stderr); va_end(a);
}
enum { W = 512 };

static NSData *payload(void) {
    NSMutableData *d = [NSMutableData dataWithLength:(W / 8) * (W / 8) * 16];
    uint8_t *p = d.mutableBytes;
    for (NSUInteger b = 0; b < d.length / 16; b++) {
        uint64_t lo = 0xFFFFFFFFFFFFFDFCull, hi = 0xFFFF000040400000ull | 0xFFFF;   // void extent, RGBA16 FFFF 4040 0000 FFFF
        memcpy(p + b * 16, &lo, 8); memcpy(p + b * 16 + 8, &hi, 8);
    }
    return d;
}

static NSUInteger sampled(id<MTLDevice> d, id<MTLCommandQueue> q, id<MTLTexture> t) {
    NSError *e = nil;
    id<MTLLibrary> lib = [d newLibraryWithSource:@"#include <metal_stdlib>\nusing namespace metal;\n"
        "kernel void k(texture2d<float, access::sample> t [[texture(0)]], device uchar4 *o [[buffer(0)]], uint2 g [[thread_position_in_grid]]) {\n"
        "  constexpr sampler s(coord::pixel, filter::nearest); o[g.y * 512 + g.x] = uchar4(round(saturate(t.sample(s, float2(g) + 0.5)) * 255.0)); }\n"
        options:nil error:&e];
    id<MTLComputePipelineState> ps = [d newComputePipelineStateWithFunction:[lib newFunctionWithName:@"k"] error:&e];
    if (!ps) { printf("kernel: %s\n", e.localizedDescription.UTF8String); exit(1); }
    id<MTLBuffer> out = [d newBufferWithLength:W * W * 4 options:MTLResourceStorageModeShared];
    memset(out.contents, 0xEE, out.length);
    id<MTLCommandBuffer> cb = [q commandBuffer]; id<MTLComputeCommandEncoder> ce = [cb computeCommandEncoder];
    [ce setComputePipelineState:ps]; [ce setTexture:t atIndex:0]; [ce setBuffer:out offset:0 atIndex:0];
    [ce dispatchThreads:MTLSizeMake(W, W, 1) threadsPerThreadgroup:MTLSizeMake(8, 8, 1)]; [ce endEncoding];
    [cb commit]; [cb waitUntilCompleted];
    const uint8_t *p = out.contents; NSUInteger n = 0;
    for (NSUInteger i = 0; i < W * W; i++) n += p[4 * i] == 255 && p[4 * i + 1] == 64 && p[4 * i + 2] == 0 && p[4 * i + 3] == 255;
    return n;
}

int main(void) { @autoreleasepool {
    id<MTLDevice> d = MTLCreateSystemDefaultDevice(); id<MTLCommandQueue> q = [d newCommandQueue];
    id<MTLBlitCommandEncoder> b0 = [[q commandBuffer] blitCommandEncoder]; Class blit = object_getClass(b0); [b0 endEncoding];
    // on the HD 4000 the driver already loaded libargbuf with its hooks installed: installing them twice would decode twice
    if (strcmp(class_getName(object_getClass(d)), "MTLIGAccelDevice")) agb_astc_install(object_getClass(d), Nil, blit, log_line);
    else printf("device %s: libargbuf hooks from the driver\n", d.name.UTF8String);
    NSData *data = payload(); const NSUInteger bpr = (W / 8) * 16;
    MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatASTC_8x8_LDR width:W height:W mipmapped:NO];
    td.usage = MTLTextureUsageShaderRead; td.storageMode = MTLStorageModeManaged;

    id<MTLTexture> r = [d newTextureWithDescriptor:td];
    BOOL up = r.pixelFormat == MTLPixelFormatASTC_8x8_LDR;   // WeatherMaps: guard texture.pixelFormat == format
    if (up) [r replaceRegion:MTLRegionMake2D(0, 0, W, W) mipmapLevel:0 withBytes:data.bytes bytesPerRow:bpr];
    printf("R reported %lu uploaded %s texels %lu/%d\n", (unsigned long)r.pixelFormat, up ? "yes" : "no", (unsigned long)sampled(d, q, r), W * W);

    id<MTLTexture> t = [d newTextureWithDescriptor:td];
    id<MTLBuffer> src = [d newBufferWithBytes:data.bytes length:data.length options:MTLResourceStorageModeShared];
    up = t.pixelFormat == MTLPixelFormatASTC_8x8_LDR;
    if (up) {
        id<MTLCommandBuffer> cb = [q commandBuffer]; id<MTLBlitCommandEncoder> be = [cb blitCommandEncoder];
        [be copyFromBuffer:src sourceOffset:0 sourceBytesPerRow:bpr sourceBytesPerImage:data.length sourceSize:MTLSizeMake(W, W, 1)
                 toTexture:t destinationSlice:0 destinationLevel:0 destinationOrigin:MTLOriginMake(0, 0, 0) options:MTLBlitOptionNone];
        [be endEncoding]; [cb commit]; [cb waitUntilCompleted];
    }
    printf("B reported %lu uploaded %s texels %lu/%d\n", (unsigned long)t.pixelFormat, up ? "yes" : "no", (unsigned long)sampled(d, q, t), W * W);
    // an ordinary texture of the same class is untouched
    id<MTLTexture> plain = [d newTextureWithDescriptor:[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:4 height:4 mipmapped:NO]];
    printf("P reported %lu\n", (unsigned long)plain.pixelFormat);
} return 0; }
