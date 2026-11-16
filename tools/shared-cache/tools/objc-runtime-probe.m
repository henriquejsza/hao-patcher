// Derived from the archive's other-cache-optimizations/objc-probe.m (2026-10-24).
// Diagnostic helper only: observe its own process, never change runtime options.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <uuid/uuid.h>

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "foundation") && strcmp(argv[1], "metal"))) {
        fprintf(stderr, "usage: objc-probe foundation|metal\n");
        return 2;
    }
    bool (*overridden)(void) = dlsym(RTLD_DEFAULT, "dyld_shared_cache_some_image_overridden");
    bool (*getuuid)(uuid_t) = dlsym(RTLD_DEFAULT, "_dyld_get_shared_cache_uuid");
    uuid_t id;
    char cache_uuid[37];
    if (!overridden || !getuuid || !getuuid(id)) { fprintf(stderr, "cache API unavailable\n"); return 3; }
    uuid_unparse_lower(id, cache_uuid);
    printf("cache_uuid=%s\n", cache_uuid);
    printf("override_before=%d\n", overridden());
    @autoreleasepool {
        Class cls = objc_getClass("NSString");
        SEL sel = sel_registerName("length");
        Protocol *protocol = objc_getProtocol("NSCopying");
        NSString *value = [NSString stringWithUTF8String:"cache-probe"];
        BOOL conforms = [value conformsToProtocol:protocol];
        printf("class=%d selector=%d protocol=%d conforms=%d length=%lu\n",
               cls != Nil, sel != NULL, protocol != nil, conforms, (unsigned long)[value length]);
        if (!cls || !sel || !protocol || !conforms || value.length != 11) return 4;
        if (!strcmp(argv[1], "metal")) {
            void *handle = dlopen("/System/Library/Frameworks/Metal.framework/Versions/A/Metal", RTLD_NOW | RTLD_LOCAL);
            printf("metal_loaded=%d\n", handle != NULL);
            if (!handle) { fprintf(stderr, "%s\n", dlerror()); return 5; }
        }
    }
    printf("override_after=%d\n", overridden());
    return 0;
}
