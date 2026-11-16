// probe18.m: do textures and render pipelines made through libargbuf's device hooks go away when released?
//   T1  N x newTextureWithDescriptor: (1024x1024 RGBA8, Private, render target) released in a pool
//   T2  N x newTextureWithDescriptor: MSAA Stencil8 Managed (the storage rule's adapted case)
//   T3  N x newRenderPipelineStateWithDescriptor:error: (tiny vertex/fragment pair)
// Each prints how many of the N objects were destroyed (weak references cleared) and the phys_footprint change.
// A hook that retains its +1 result again leaks every object: "destroyed 0/N" and footprint growth.
// Run on the laptop: probe18 [N]   (default 200)
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <mach/mach.h>

static double footprint_mb(void) {
    task_vm_info_data_t info; mach_msg_type_number_t n = TASK_VM_INFO_COUNT;
    return task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &n) == KERN_SUCCESS ? info.phys_footprint / 1048576.0 : -1;
}

static void run(const char *name, int count, id (^make)(void)) {
    NSPointerArray *weak = [NSPointerArray weakObjectsPointerArray];
    double before = footprint_mb();
    for (int i = 0; i < count; i++) @autoreleasepool {
        id o = make();
        if (!o) { printf("%s: creation %d failed\n", name, i); return; }
        [weak addPointer:(__bridge void *)o];
    }
    unsigned long alive = 0;
    for (NSUInteger i = 0; i < weak.count; i++) if ([weak pointerAtIndex:i]) alive++;
    double after = footprint_mb();
    printf("%s: destroyed %lu/%d, footprint %+.1f MB (%.1f -> %.1f)\n", name, (unsigned long)count - alive, count,
           after - before, before, after);
}

static NSString *src = @
"#include <metal_stdlib>\n"
"using namespace metal;\n"
"vertex float4 v(uint i [[vertex_id]]) { return float4(float(i & 1), float(i >> 1), 0, 1); }\n"
"fragment float4 f() { return float4(1, 0, 0, 1); }\n";

int main(int argc, char **argv) { @autoreleasepool {
    int n = argc > 1 ? atoi(argv[1]) : 200;
    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { printf("no Metal device\n"); return 1; }
    printf("device %s, %d each\n", dev.name.UTF8String, n);
    run("T1 texture private", n, ^id {
        MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
                                                                                     width:1024 height:1024 mipmapped:NO];
        d.storageMode = MTLStorageModePrivate; d.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
        return [dev newTextureWithDescriptor:d]; });
    run("T2 texture msaa stencil managed", n, ^id {
        MTLTextureDescriptor *d = [MTLTextureDescriptor new]; d.textureType = MTLTextureType2DMultisample; d.sampleCount = 4;
        d.pixelFormat = MTLPixelFormatStencil8; d.width = d.height = 512; d.storageMode = MTLStorageModeManaged;
        d.usage = MTLTextureUsageRenderTarget;
        return [dev newTextureWithDescriptor:d]; });
    NSError *e = nil;
    id<MTLLibrary> lib = [dev newLibraryWithSource:src options:nil error:&e];
    if (!lib) { printf("T3: library: %s\n", e.description.UTF8String); return 1; }
    id<MTLFunction> vf = [lib newFunctionWithName:@"v"], ff = [lib newFunctionWithName:@"f"];
    run("T3 render pipeline", n, ^id {
        MTLRenderPipelineDescriptor *p = [MTLRenderPipelineDescriptor new];
        p.vertexFunction = vf; p.fragmentFunction = ff; p.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
        NSError *pe = nil;
        id s = [dev newRenderPipelineStateWithDescriptor:p error:&pe];
        if (!s) printf("T3: %s\n", pe.description.UTF8String);
        return s; });
    return 0;
}}
