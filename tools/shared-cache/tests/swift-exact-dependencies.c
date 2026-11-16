// Exercise the collector itself with lazy singleton metadata and runtime callbacks.
#define main collector_main
#define SWIFT_WITNESS_GRAPH
#include "../tools/swift-graph.c"
#undef main
#include <assert.h>

static uint32_t value_descriptor[16]={17}, class_descriptor[16]={16};
static uint32_t parent_descriptor[16]={17|128};
static uintptr_t value_metadata[3]={0x200,0,0}, class_metadata[3]={0x123,0,0};
static uintptr_t parent_metadata[3]={0x200,0,0};
static unsigned initialized, parent_calls, context_calls;
static const void *parent_result=parent_metadata;
static int wrong_identity, incomplete;
static const void *canonical_static;
static int state_disagrees, state_incomplete;
int swift_witness_graph_start(void) { return 0; }
void swift_witness_graph_finish(int (*callback)(const uintptr_t *,unsigned)) { (void)callback; }
int swift_graph_compiler_static(const void *m) { return m==canonical_static; }
const char *swift_graph_generic_arguments(const void *d,const void **args,size_t count,size_t capacity) {
    (void)d; (void)args; (void)count; (void)capacity; return "not exercised by this fixture";
}
unsigned swift_graph_metadata_kind(const void *m) { return (unsigned)*(const uintptr_t *)m; }
int swift_graph_capture_metatype(const void *m,unsigned depth,int (*callback)(const uintptr_t *,unsigned),int (*contains)(uintptr_t)) {
    (void)m; (void)depth; (void)callback; (void)contains; return -1;
}
static Response __attribute__((swiftcall)) metadata_state(uintptr_t request,const void *m) {
    assert(request==0 && m==value_metadata);
    return (Response){state_disagrees?parent_metadata:class_metadata,state_incomplete};
}
static const uint32_t * __attribute__((swiftcall)) context(const void *p) {
    context_calls++;
    return (const void*)((const uintptr_t*)p)[1];
}
static Response __attribute__((swiftcall)) value_access(uintptr_t request) {
    assert(request==0); initialized|=1;
    return (Response){wrong_identity?class_metadata:value_metadata,incomplete};
}
static Response __attribute__((swiftcall)) class_access(uintptr_t request) {
    assert(request==0); initialized|=2;
    return (Response){class_metadata,0};
}
static Response __attribute__((swiftcall)) parent_access(uintptr_t request,const void *const *args,const void *d) {
    assert(request==0 && d==parent_descriptor && args[0]==value_metadata);
    assert(initialized&1); parent_calls++;
    return (Response){parent_result,0};
}
int main(void) {
    cache_start=1; cache_end=UINTPTR_MAX;
    getcontext=context; generic=parent_access;
    value_metadata[1]=(uintptr_t)value_descriptor;
    class_metadata[1]=(uintptr_t)class_descriptor;
    parent_metadata[1]=(uintptr_t)parent_descriptor;
    parent_metadata[2]=(uintptr_t)value_metadata;
    intptr_t delta=(char*)value_access-(char*)(value_descriptor+3);
    assert(delta== (int32_t)delta); value_descriptor[3]=(int32_t)delta;
    delta=(char*)class_access-(char*)(class_descriptor+3);
    assert(delta==(int32_t)delta); class_descriptor[3]=(int32_t)delta;
    uint16_t *g=(void*)(parent_descriptor+9); g[0]=g[2]=1;
    assert(cached((uintptr_t)value_metadata));
    assert(!prepare_argument(parent_metadata,0));
    assert(parent_calls==1 && initialized==1);
    assert(!prepare_argument(class_metadata,0) && initialized==3);
    wrong_identity=1;
    assert(strstr(prepare_argument(value_metadata,0),"canonical identity"));
    value_descriptor[0]|=2u<<16; checkstate=metadata_state;
    assert(!prepare_argument(value_metadata,0));
    state_disagrees=1;
    assert(strstr(prepare_argument(value_metadata,0),"canonical identity"));
    state_disagrees=0; state_incomplete=1;
    assert(strstr(prepare_argument(value_metadata,0),"canonical identity"));
    state_incomplete=0; value_descriptor[0]=17;
    wrong_identity=0; incomplete=1;
    assert(strstr(prepare_argument(value_metadata,0),"canonical identity"));
    incomplete=0;
    uintptr_t *heap=calloc(3,sizeof(*heap)); assert(heap);
    assert(strstr(prepare_argument(heap,0),"not in a cache image"));
    uintptr_t known=(uintptr_t)heap; installed_metadata=&known; installed_count=1;
    memcpy(heap,parent_metadata,sizeof(parent_metadata)); parent_result=heap;
    unsigned calls=context_calls;
    assert(!prepare_argument(heap,0) && context_calls==calls+2 && parent_calls==2);
    installed_count=0; installed_metadata=NULL; free(heap);
    canonical_static=parent_metadata; calls=parent_calls;
    assert(!prepare_argument(parent_metadata,0) && parent_calls==calls);
    canonical_static=NULL;
    class_descriptor[0]|=128;
    assert(strstr(prepare_argument(class_metadata,0),"generic class"));
    assert(strstr(prepare_argument(value_metadata,129),"recursive"));
    puts("lazy value/class initialization, dependency order, canonical identity and installed metadata: PASS");
}
