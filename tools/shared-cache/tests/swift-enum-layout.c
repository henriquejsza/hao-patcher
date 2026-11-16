// Link with swift-enum-layout.swift; exercises the matching runtime's witnesses.
#define main collector_main
#include "../tools/swift-graph.c"
#undef main
#include <assert.h>

int exercise_enum_layout(const void *value,const uintptr_t *m) {
    size_t size=0;
    const void *(*range)(size_t*)=dlsym(RTLD_DEFAULT,"_dyld_get_shared_cache_range");
    cache_start=(uintptr_t)range(&size); cache_end=cache_start+size;
    void *lib=dlopen("/usr/lib/swift/libswiftCore.dylib",RTLD_NOW|RTLD_LOCAL);
    generic=dlsym(lib,"swift_getGenericMetadata"); getname=dlsym(lib,"swift_getMangledTypeName");
    if(m[0]!=0x201 && m[0]!=0x202) return 0;
    const uint32_t *d=(const void*)m[1];
    if(!(d[0]&0x100000)) return 0;
    const uint32_t *pattern=(const void*)((const char*)(d+8)+(int32_t)d[8]);
    const uint16_t *g=(const void*)(d+9);
    unsigned end=2+g[2];
    if(d[5]>>24) end++;
    if(pattern[2]&2) end++;
    uintptr_t *allocation=metadata_copy(m,d,end),*clone=allocation+2;
    const uintptr_t *layout=(const void*)m[-2]; size_t length=layout[1]+24;
    assert(!layout[0] && length<65560);
    void *copied_layout=malloc(length); assert(copied_layout);
    memcpy(copied_layout,layout,length); clone[-2]=(uintptr_t)copied_layout;
    struct LayoutReader reader={copied_layout,m,0,0,NULL};
    assert(layout_program(&reader,16,length,1,0)==length && !reader.error);
    const uintptr_t *w=(const void*)m[-1];
    void *copy=calloc(1,w[9]); assert(copy);
    typedef void *Copy(void *,const void *,const void *);
    typedef void Destroy(void *,const void *);
    typedef unsigned Tag(const void *,const void *);
    assert(((Copy*)w[2])(copy,value,clone)==copy);
    assert(((Tag*)w[11])(copy,clone)==((Tag*)w[11])(value,m));
    assert(!memcmp(copy,value,w[8]));
    ((Destroy*)w[1])(copy,clone);
    printf("PASS enum layout opcode 0x%02llx, %zu bytes, tag %u\n",
           (unsigned long long)(layout[2]>>56),length,((Tag*)w[11])(value,m));
    free(copy);free(copied_layout);free(allocation);
    return 1;
}
