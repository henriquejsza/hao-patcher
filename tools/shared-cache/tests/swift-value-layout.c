// Native ABI exercise. Includes the collector so its section classifier is used.
// Build x86_64 and sign before running; see README Verify.
#define main collector_main
#include "../tools/swift-graph.c"
#undef main
#include <assert.h>
#include <sys/mman.h>

typedef void *Copy(void *, const void *, const void *);
typedef void Destroy(void *, const void *);
typedef void Inject(void *, unsigned, const void *);
typedef unsigned Tag(const void *, const void *);

static Name unexpected_name(const void *m) __attribute__((swiftcall));
static Name unexpected_name(const void *m) { (void)m; abort(); }

int main(void) {
    // A metadata header without HasLayoutString need not expose m[-2] at all.
    // Put that word in an unreadable page: the production copier must not read it.
    size_t page=(size_t)getpagesize();
    char *guard=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    assert(guard!=MAP_FAILED && !mprotect(guard,page,PROT_NONE));
    uintptr_t *minimal=(void*)(guard+page+8);
    minimal[-1]=0x1234; minimal[0]=0x200; minimal[1]=0x5678;
    uint32_t descriptor[7]={0xd1};
    uintptr_t *copied=metadata_copy(minimal,descriptor,2);
    assert(!copied[0] && copied[1]==0x1234 && copied[2]==0x200 && copied[3]==0x5678);
    free(copied); munmap(guard,2*page);
    puts("PASS absent layout prefix is never read");
    void *lib=dlopen("/usr/lib/swift/libswiftCore.dylib",RTLD_NOW|RTLD_LOCAL);
    assert(lib && dlopen("/System/Library/Frameworks/SwiftUI.framework/SwiftUI",RTLD_NOW|RTLD_LOCAL));
    assert(dlopen("/System/Library/PrivateFrameworks/AttributeGraph.framework/AttributeGraph",RTLD_NOW|RTLD_LOCAL));
    Resolve *get=dlsym(lib,"swift_getTypeByMangledNameInContext");
    size_t size; const void *(*range)(size_t*)=dlsym(RTLD_DEFAULT,"_dyld_get_shared_cache_range");
    cache_start=(uintptr_t)range(&size); cache_end=cache_start+size;
    const char *names[]={
        "7SwiftUI11_GraphValueVySiG",
        "14AttributeGraph13PointerOffsetVySiSiG",
        "14AttributeGraph9AttributeVySiG",
        "7SwiftUI15ModifiedContentVyAA9EmptyViewVAA14_PaddingLayoutVG",
        "7SwiftUI11_GraphValueVyAA15ModifiedContentVyAA9EmptyViewVAA14_PaddingLayoutVGG",
        "7SwiftUI11_GraphValueVySiGSg"
    };
    for(unsigned i=0;i<sizeof(names)/sizeof(*names);i++) {
        const uintptr_t *m=get(names[i],strlen(names[i]),NULL,NULL);
        assert(m && (m[0]==0x200 || m[0]==0x202));
        const uint32_t *d=(const void*)m[1];
        const uint32_t *p=(const void*)((const char*)(d+8)+(int32_t)d[8]);
        const uint16_t *g=(const void*)(d+9);
        unsigned end=2+g[2];
        if(m[0]==0x200 && d[6]) end=d[6]+(d[5]+1)/2;
        if(m[0]==0x202 && d[5]>>24) end++;
        if(p[2]&2) end++;
        const uintptr_t *w=(const void*)m[-1]; unsigned nw=(w[10]&0x200000)?14:11;
        uintptr_t *allocation=calloc(end+2+nw,8), *clone=allocation+2;
        assert(allocation && !(w[10]&0x10000)); // only POD samples can be fabricated
        uintptr_t *serialized=metadata_copy(m,d,end);
        memcpy(allocation,serialized,(end+2)*8); free(serialized);
        memcpy(allocation+end+2,w,nw*8); clone[-1]=(uintptr_t)(allocation+end+2);
        void *a=calloc(1,w[9]),*b=calloc(1,w[9]); assert(a && b);
        if(m[0]==0x202) ((Inject*)w[13])(a,1,clone);
        assert(((Copy*)w[2])(b,a,clone)==b && memcmp(a,b,w[8])==0);
        if(m[0]==0x202) assert(((Tag*)w[11])(b,clone)==1);
        ((Destroy*)w[1])(a,clone); ((Destroy*)w[1])(b,clone);
        // A fresh ModifiedContent resides in libswiftCore's zero-fill pool.
        // It must be followed as an owned dependency, never serialized as an image offset.
        if(i==4) assert(!cached(m[2]));
        printf("PASS %s\n",names[i]); free(a); free(b); free(allocation);
    }
    // A failed dependency must stop the parent before Swift's name builder.
    generic=dlsym(lib,"swift_getGenericMetadata"); getname=unexpected_name;
    const char *function="SiycSg";
    const uintptr_t *unsupported=get(function,strlen(function),NULL,NULL);
    assert(unsupported && !capture(unsupported,0));
    assert(!capture(unsupported,0)); // A previously rejected node stays rejected.
    puts("PASS unsupported function dependency never remangled");
    return 0;
}
