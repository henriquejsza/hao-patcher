// Use the actual runtime to compare recursive construction with ordinary lookup.
#define main collector_main
#include "../tools/swift-graph.c"
#undef main
#include <assert.h>
int main(void) {
    size_t size=0;
    const void *(*range)(size_t*)=dlsym(RTLD_DEFAULT,"_dyld_get_shared_cache_range");
    cache_start=(uintptr_t)range(&size);cache_end=cache_start+size;
    void *lib=dlopen("/usr/lib/swift/libswiftCore.dylib",RTLD_NOW|RTLD_LOCAL);assert(lib);
    resolve=dlsym(lib,"swift_getTypeByMangledNameInContext");
    generic=dlsym(lib,"swift_getGenericMetadata");getcontext=dlsym(lib,"swift_getTypeContextDescriptor");
    assert(resolve && generic && getcontext);
    const void *optional=resolve("SiSg",4,NULL,NULL);assert(optional);
    uintptr_t descriptor=(uintptr_t)getcontext(optional)-cache_start;
    char leaf[]="1\tSi";construct(0,leaf,1);
    char child[100];snprintf(child,sizeof(child),"2\t%llx\t1",(unsigned long long)descriptor);construct(1,child,1);
    char parent[100];snprintf(parent,sizeof(parent),"3\t%llx\t2",(unsigned long long)descriptor);construct(1,parent,1);
    assert(!definition("3")->error && definition("3")->metadata==resolve("SiSgSg",6,NULL,NULL));
    char missing[]="4\tNotARealSwiftType";construct(0,missing,1);
    char blocked[100];snprintf(blocked,sizeof(blocked),"5\t%llx\t4",(unsigned long long)descriptor);construct(1,blocked,1);
    assert(definition("5")->error && !definition("5")->metadata);
    puts("canonical recursive constructor and failed dependency propagation: PASS");
    free(definitions);
}
