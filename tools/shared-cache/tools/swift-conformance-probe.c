// Self-process diagnostics using the installed runtime; never force its gates.
// ABI: Swift Metadata.h/RuntimeFunctions.def and Apple's mach-o/dyld_priv.h.
#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <uuid/uuid.h>

typedef const void * __attribute__((swiftcall)) Resolve(const char *, size_t, const void *, const void *const *);
typedef const void * __attribute__((swiftcall)) Conforms(const void *, const void *);
typedef struct { uintptr_t kind; const void *value; } Result;
typedef Result Lookup(const void *, const void *, const void *);

int main(int argc, char **argv) {
    if (argc < 2 || (strcmp(argv[1], "runtime") && strcmp(argv[1], "table"))) {
        fputs("usage: swift-conformance-probe runtime|table [IMAGE ...]\n", stderr); return 2;
    }
    bool direct = !strcmp(argv[1], "table");
    void *core = dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_NOW | RTLD_GLOBAL);
    if (!core) { fprintf(stderr, "%s\n", dlerror()); return 3; }
    for (int i = 2; i < argc; ++i) {
        if (!dlopen(argv[i], RTLD_NOW | RTLD_LOCAL)) {
            fprintf(stderr, "%s: %s\n", argv[i], dlerror()); return 3;
        }
    }
    Resolve *resolve = dlsym(core, "swift_getTypeByMangledNameInContext");
    Conforms *conforms = dlsym(core, "swift_conformsToProtocol");
    Lookup *lookup = dlsym(RTLD_DEFAULT, "_dyld_find_protocol_conformance");
    bool (*overridden)(void) = dlsym(RTLD_DEFAULT, "dyld_shared_cache_some_image_overridden");
    bool (*getuuid)(uuid_t) = dlsym(RTLD_DEFAULT, "_dyld_get_shared_cache_uuid");
    uuid_t uuid;
    if (!resolve || !conforms || !lookup || !overridden || !getuuid || !getuuid(uuid)) {
        fputs("runtime API unavailable\n", stderr); return 3;
    }
    char id[37]; uuid_unparse_lower(uuid, id);
    printf("{\"cache_uuid\":\"%s\",\"override\":%s,\"mode\":\"%s\"}\n",
           id, overridden() ? "true" : "false", argv[1]);
    const char *names[] = {"Int", "String", "Double"};
    const char *mangled[] = {"Si", "SS", "Sd"};
    const char *protocols[] = {"Equatable", "Hashable", "Encodable", "Decodable"};
    const char *symbols[] = {"$sSQMp", "$sSHMp", "$sSEMp", "$sSeMp"};
    unsigned failures = 0;
    for (unsigned i = 0; i < 3; ++i) {
        const uintptr_t *metadata = resolve(mangled[i], strlen(mangled[i]), NULL, NULL);
        // All three requested types are structs: descriptor is word one.
        if (!metadata || metadata[0] != 0x200) { fputs("unexpected metadata kind\n", stderr); return 4; }
        for (unsigned j = 0; j < 4; ++j) {
            const void *protocol = dlsym(core, symbols[j]);
            if (!protocol) { fprintf(stderr, "missing %s\n", symbols[j]); return 4; }
            if (direct) {
                Result r = lookup(protocol, metadata, (const void *)metadata[1]);
                printf("{\"type\":\"%s\",\"protocol\":\"%s\",\"kind\":%lu,\"value\":%llu}\n",
                       names[i], protocols[j], (unsigned long)r.kind, (unsigned long long)r.value);
                failures += r.kind > 1 || !r.value;
            } else {
                const void *witness = conforms(metadata, protocol);
                printf("{\"type\":\"%s\",\"protocol\":\"%s\",\"metadata\":%llu,\"type_descriptor\":%llu,\"protocol_descriptor\":%llu,\"witness\":%llu}\n",
                       names[i], protocols[j], (unsigned long long)metadata,
                       (unsigned long long)metadata[1], (unsigned long long)protocol,
                       (unsigned long long)witness);
                failures += !witness;
            }
        }
    }
    printf("{\"complete\":true,\"failures\":%u}\n", failures);
    return failures ? 1 : 0;
}
