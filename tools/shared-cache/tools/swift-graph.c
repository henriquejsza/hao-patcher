// Discover and regenerate generic value metadata with the matching Swift runtime.
// ABI: swiftlang/swift include/swift/ABI/{Metadata,GenericContext,MetadataValues}.h.
// Only fields described by that ABI are serialized; no pointer-shaped-word scan.
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>

#ifdef SWIFT_WITNESS_GRAPH
extern int swift_witness_graph_start(void);
extern void swift_witness_graph_finish(int (*capture)(const uintptr_t *, unsigned));
extern int swift_graph_compiler_static(const void *metadata);
extern unsigned swift_graph_metadata_kind(const void *metadata);
extern int swift_graph_capture_metatype(const void *, unsigned, int (*)(const uintptr_t *, unsigned), int (*)(uintptr_t));
extern const char *swift_graph_generic_arguments(const void *, const void **, size_t, size_t);
#endif

typedef const void * __attribute__((swiftcall)) Resolve(const char *, size_t, const void *, const void *const *);
typedef struct { const void *value; uintptr_t state; } Response;
typedef Response __attribute__((swiftcall)) Generic(uintptr_t, const void *const *, const void *);
typedef struct { const char *data; size_t length; } Name;
typedef Name __attribute__((swiftcall)) GetName(const void *);
static Resolve *resolve;
static Generic *generic;
typedef Response __attribute__((swiftcall)) CheckState(uintptr_t, const void *);
static CheckState *checkstate;
static const void *(*getmetatype)(const void *);
static GetName *getname;
typedef const uint32_t * __attribute__((swiftcall)) GetContext(const void *);
static GetContext *getcontext;
typedef Response __attribute__((swiftcall)) Opaque(uintptr_t, const void *const *, const void *, unsigned);
typedef const void * __attribute__((swiftcall)) Conforms(const void *, const void *);
static Opaque *getopaque;
static Conforms *conforms;
static uintptr_t cache_start, cache_end;
static uintptr_t *installed_metadata;
static size_t installed_count;
struct Captured { const uintptr_t *metadata; int supported; };
static struct Captured *visited;
static size_t visited_count;
static void fail(const char *s) { fprintf(stderr,"%s\n",s); exit(2); }
static int constructor_image_loaded(uintptr_t pointer) {
    Dl_info image={};
    if(!dladdr((const void*)pointer,&image) || !image.dli_fname) return 0;
    void *handle=dlopen(image.dli_fname,RTLD_LAZY|RTLD_LOCAL|RTLD_NOLOAD);
    if(!handle) return 0;
    dlclose(handle);
    return 1;
}
#include "cache-address.h"
static int cached(uintptr_t p) {
    return file_backed_cache_pointer(p, cache_start, cache_end);
}

static void string(const char *s, size_t n) {
    putchar('"');
    for (size_t i=0;i<n;i++) {
        unsigned char c=s[i];
        if (c=='"' || c=='\\') printf("\\%c",c);
        else if (c<32) printf("\\u%04x",c);
        else putchar(c);
    }
    putchar('"');
}
static void words(const uintptr_t *p,size_t n) {
    putchar('[');
    for(size_t i=0;i<n;i++) printf("%s%llu",i?",":"",(unsigned long long)p[i]);
    putchar(']');
}
static void rejected(const uintptr_t *m,const char *reason) {
    printf("{\"node\":%llu,\"status\":\"unsupported\",\"reason\":",(unsigned long long)m);
    string(reason,strlen(reason));
#ifdef SWIFT_WITNESS_GRAPH
    printf(",\"metadata_kind\":%u",swift_graph_metadata_kind(m));
#endif
    puts("}");
}
#define REJECT(s) do { rejected(m,s); return 0; } while(0)
static uintptr_t *metadata_copy(const uintptr_t *m,const uint32_t *d,unsigned end) {
    uintptr_t *copy=malloc((end+2)*sizeof(*copy));
    if(!copy) fail("allocation failed");
    copy[0]=(d[0]&0x100000)?m[-2]:0;
    memcpy(copy+1,m-1,(end+1)*sizeof(*copy));
    // Struct field offsets are uint32_t; the final half-word is padding.
    if((d[0]&31)==17 && d[6] && (d[5]&1)) ((uint32_t*)(copy+2+d[6]))[d[5]]=0;
    return copy;
}
static int capture(const uintptr_t *m, unsigned depth);
struct LayoutReader {
    const unsigned char *bytes;
    const uintptr_t *metadata;
    unsigned depth;
    uintptr_t dependency;
    const char *error;
};
static uint64_t layout_word(struct LayoutReader *r,size_t at,size_t end) {
    uint64_t value=0;
    if(at>end || end-at<8) r->error="truncated runtime layout operand";
    else memcpy(&value,r->bytes+at,8);
    return value;
}
static void layout_reference(struct LayoutReader *r,size_t at,size_t end,int executable,int nullable) {
    uintptr_t p=layout_word(r,at,end);
    if(r->error) return;
    if(!p) { if(!nullable) r->error="null runtime layout reference"; return; }
    if(cached(p) || p==(uintptr_t)r->metadata) return;
    if(executable) { r->error="layout function is outside shared cache"; return; }
    if(!capture((const void*)p,r->depth+1)) {
        r->dependency=p; r->error="unsupported layout metadata dependency";
    }
}
static size_t layout_program(struct LayoutReader *r,size_t pos,size_t end,int terminated,unsigned depth) {
    if(depth>128) { r->error="runtime layout nesting exceeds supported depth"; return pos; }
    while(pos<end && !r->error) {
        unsigned tag=(unsigned)(layout_word(r,pos,end)>>56); pos+=8;
        if(!tag) {
            if(!terminated) r->error="unexpected End in runtime layout payload";
            return pos;
        }
        if((tag>=1 && tag<=11) || tag==14) continue;
        if(tag==12) { layout_reference(r,pos,end,0,0); pos+=8; }
        else if(tag==16 || tag==18 || tag==19) {
            size_t count;
            if(tag==16) { count=layout_word(r,pos+32,end); pos+=48; }
            else if(tag==18) {
                layout_reference(r,pos,end,1,0);
                count=layout_word(r,pos+8,end); pos+=24;
            } else {
                layout_reference(r,pos+16,end,0,1);
                count=layout_word(r,pos+28,end); pos+=44;
            }
            if(pos>end || count>end-pos) { r->error="runtime layout payload exceeds program"; return pos; }
            layout_program(r,pos,pos+count,0,depth+1); pos+=count;
        } else if(tag==21 || tag==22) {
            if(tag==21) layout_reference(r,pos,end,1,0);
            else {
                uint64_t width=layout_word(r,pos,end);
                if(width!=0 && width!=1 && width!=2 && width!=4) r->error="unsupported runtime enum tag width";
            }
            size_t count=layout_word(r,pos+8,end), size=layout_word(r,pos+16,end);
            (void)layout_word(r,pos+24,end); pos+=32;
            if(pos>end || count>(end-pos)/8 || size>end-pos-count*8) {
                r->error="runtime layout branches exceed program"; return pos;
            }
            size_t start=pos+count*8, finish=start+size;
            for(size_t i=0;i<count && !r->error;i++) {
                size_t offset=layout_word(r,pos+8*i,end);
                if(offset>=size) { r->error="runtime layout branch offset outside payload"; return pos; }
                layout_program(r,start+offset,finish,1,depth+1);
            }
            pos=finish;
        } else { r->error="unsupported runtime layout opcode"; return pos; }
    }
    if(terminated && !r->error) r->error="runtime layout string has no End";
    return pos;
}

static int capture(const uintptr_t *m, unsigned depth) {
    for(size_t i=0;i<visited_count;i++) if(visited[i].metadata==m) return visited[i].supported;
    visited=realloc(visited,(visited_count+1)*sizeof(*visited));
    if(!visited) fail("allocation failed");
    size_t slot=visited_count++;
    visited[slot]=(struct Captured){m,0};
    if(depth>128) REJECT("recursive dependency depth exceeds supported layout");
#ifdef SWIFT_WITNESS_GRAPH
    int metatype=swift_graph_capture_metatype(m,depth,capture,cached);
    if(metatype>=0) { visited[slot].supported=metatype; return metatype; }
    if(cached((uintptr_t)m)) {
        const uint32_t *context=getcontext(m);
        if(context && cached((uintptr_t)context) && swift_graph_compiler_static(m)) {
            Name name=getname(m);
            if(!name.data || !name.length) REJECT("compiler metadata name unavailable");
            printf("{\"node\":%llu,\"status\":\"compiler_static\",\"canonical\":true,\"static_specialization\":true,\"descriptor\":%llu,\"name\":",
                   (unsigned long long)m,(unsigned long long)context);
            string(name.data,name.length); puts("}");
            visited[slot].supported=1;
            return 1;
        }
    }
#endif
    if(m[0]!=0x200 && m[0]!=0x201 && m[0]!=0x202) REJECT("metadata kind is not struct or enum");
    const uint32_t *d=(const void*)m[1];
    if(!cached((uintptr_t)d)) REJECT("type descriptor is outside shared cache");
    unsigned kind=d[0]&31;
    if(!(d[0]&128) || (kind!=17 && kind!=18)) REJECT("not generic value metadata");
    const uint16_t *g=(const void*)(d+9);
    unsigned params=g[0], requirements=g[1], count=g[2];
    // Conditional inverted protocols trail requirements without changing keys.
    if((g[3]&~2u) || !count || count>63 || params>count) REJECT("packs or extended generic context");
    const unsigned char *param=(const void*)(d+11);
    for(unsigned i=0;i<params;i++) if(param[i]!=0x80) REJECT("non-key, pack or value generic parameter");
    const uint32_t *req=(const void*)(param+((params+3)&~3u));
    unsigned keys=params;
    for(unsigned i=0;i<requirements;i++) if(req[3*i]&128) {
        if((req[3*i]&31)!=0) REJECT("non-protocol generic key requirement");
        keys++;
    }
    if(keys!=count) REJECT("generic key layout differs");
    for(unsigned i=params;i<count;i++) if(!cached(m[2+i])) {
        // Keep exact witness inputs so the constructor recorder can join every
        // blocked root to its ABI-described witness dependency graph.
        printf("{\"node\":%llu,\"status\":\"unsupported\",\"reason\":\"protocol witness dependency is outside shared cache\",\"descriptor\":%llu,\"type_arguments\":%u,\"key\":",(unsigned long long)m,(unsigned long long)d,params);
        words(m+1,count+1); puts("}");
#ifndef SWIFT_WITNESS_GRAPH
        return 0;
#else
        break; // The observer records witness closures; retain the metadata body.
#endif
    }
    const uint32_t *p=(const void*)((const char*)(d+8)+(int32_t)d[8]);
    if((p[2]>>21)!=m[0]) REJECT("pattern metadata kind differs");
    unsigned end=2+count;
    if(kind==17 && d[6]) {
        if(d[6]<end || d[6]>4096 || d[5]>4096) REJECT("unsupported field offset vector");
        end=d[6]+(d[5]+1)/2;
    }
    if(kind==18 && (d[5]>>24)) {
        if((d[5]>>24)!=end) REJECT("noncontiguous enum payload size");
        end++;
    }
    if(p[2]&2) {
        if(m[end]) REJECT("nonzero metadata trailing flags");
        end++;
    }
    if(p[2]&1) {
        const uint16_t *extra=(const void*)(p+5);
        if(2u+extra[0]+extra[1]!=end) REJECT("extra data extends beyond described metadata fields");
    }
    const uintptr_t *layout=NULL; size_t layout_size=0;
    // Only HasLayoutString makes the word before the value-witness header a
    // layout pointer. Older metadata may have unrelated storage at that address.
    if((d[0]&0x100000) && m[-2]) {
        if(!cached(m[-2])) {
            layout=(const void*)m[-2];
            // Runtime-generated strings: flags, byte count, body, End word.
            // Preserve the bytes so the host can decode typed relocations.
            if(layout[0] || layout[1]>65536) REJECT("unsupported runtime layout string header");
            layout_size=24+layout[1];
        }
    }
    const uintptr_t *w=(const void*)m[-1]; uint32_t flags=(uint32_t)w[10];
    if((flags&0x400000) || !w[9] || w[8]>w[9]) REJECT("incomplete value witnesses");
    unsigned nw=(flags&0x200000)?14:11;
    for(unsigned i=0;i<nw;i++) if((i<8 || i>10) && !cached(w[i]))
        REJECT("value witness function is outside shared cache");
    Response again=generic(0,(const void *const*)(m+2),d);
    if(again.value!=m || again.state) REJECT("metadata is incomplete or noncanonical");
    for(unsigned i=0;i<params;i++) if(!cached(m[2+i]) && !capture((const void*)m[2+i],depth+1)) {
        // Do not ask Swift to remangle an unsupported dependency closure. The
        // runtime crashed doing that for an imported-protocol function tuple.
        printf("{\"node\":%llu,\"status\":\"unsupported\",\"reason\":\"unsupported type argument dependency\",\"dependency\":%llu}\n",
               (unsigned long long)m,(unsigned long long)m[2+i]);
        return 0;
    }
    if(layout) {
        struct LayoutReader reader={(const void*)layout,m,depth,0,NULL};
        size_t finish=layout_program(&reader,16,layout_size,1,0);
        if(reader.dependency) {
            printf("{\"node\":%llu,\"status\":\"unsupported\",\"reason\":\"unsupported layout metadata dependency\",\"dependency\":%llu}\n",
                   (unsigned long long)m,(unsigned long long)reader.dependency);
            return 0;
        }
        if(reader.error) REJECT(reader.error);
        if(finish!=layout_size) REJECT("early End in runtime layout string");
    }
    Name name=getname(m); Dl_info image={0};
    if(!name.data || !name.length || !dladdr(d,&image)) REJECT("type name or owner unavailable");
    printf("{\"node\":%llu,\"status\":\"captured\",\"name\":",(unsigned long long)m);
    string(name.data,name.length); printf(",\"owner\":"); string(image.dli_fname,strlen(image.dli_fname));
    printf(",\"key\":[%llu",(unsigned long long)d);
    for(unsigned i=0;i<count;i++) printf(",%llu",(unsigned long long)m[2+i]);
    uintptr_t *copy=metadata_copy(m,d,end);
    printf("],\"type_arguments\":%u,\"full_metadata\":",params); words(copy,end+2); free(copy);
    printf(",\"witness\":"); words(w,nw);
    if(layout) {
        printf(",\"layout\":\"");
        const unsigned char *bytes=(const void*)layout;
        for(size_t i=0;i<layout_size;i++) printf("%02x",bytes[i]);
        putchar('"');
    }
    printf(",\"canonical\":true,\"descriptor_words\":");
    printf("[%u,%u,%u],\"pattern_flags\":%u}\n",d[0],d[5],d[6],p[2]);
    visited[slot].supported=1;
    return 1;
}
// A recorded static address can name lazy singleton metadata. Ordinary name
// resolution initializes it before passing it as an argument; exact-key replay
// must do the same or the parent's completion can dereference an empty cache.
static const char *prepare_argument(const uintptr_t *m, unsigned depth) {
    if(depth>128) return "exact-key dependency initialization is recursive";
    // Generated entries are complete metadata outside Apple's Mach-O sections.
    // Only offsets from the installed catalog, bound to this UUID, qualify.
    // Still call the generic API: it registers the entry in the process's
    // metadata-state cache before a parent asks for transitive completeness.
    int installed=0;
    for(size_t i=0;i<installed_count;i++) if(installed_metadata[i]==(uintptr_t)m) installed=1;
    if(!installed && !cached((uintptr_t)m)) return "exact-key dependency is not in a cache image";
    if(m[0]==0x304) {
        const char *error=prepare_argument((const void*)m[1],depth+1);
        if(error) return error;
        return getmetatype && getmetatype((const void*)m[1])==m ? NULL : "metatype canonical identity differs";
    }
    const uint32_t *d=getcontext(m);
    if(!d) return NULL; // Non-nominal and imported ObjC metadata have no Swift accessor.
    if(!cached((uintptr_t)d)) return "exact-key dependency descriptor is not cached";
    unsigned kind=d[0]&31;
    if(kind!=16 && kind!=17 && kind!=18) return "exact-key dependency descriptor kind differs";
#ifdef SWIFT_WITNESS_GRAPH
    // Match the installed verifier: compiler-canonical specializations are
    // already complete. The generic constructor need not return their identity.
    if(swift_graph_compiler_static(m)) return NULL;
#endif
    Response response;
    if(d[0]&128) {
        if(kind==16) return "unsupported cached generic class dependency";
        const uint16_t *g=(const void*)(d+9);
        if(g[0]>g[2] || g[2]>63 || (g[3]&~2u)) return "unsupported exact-key dependency context";
        for(unsigned i=0;i<g[0];i++) {
            const char *error=prepare_argument((const void*)m[2+i],depth+1);
            if(error) return error;
        }
        response=generic(0,(const void *const*)(m+2),d);
    } else {
        if(!d[3]) return NULL; // Imported static value metadata may have no accessor.
        typedef Response __attribute__((swiftcall)) Access(uintptr_t);
        Access *access=(void*)((const char*)(d+3)+(int32_t)d[3]);
        response=access(0);
    }
    // ForeignMetadataCache uniques duplicate image templates. Preserve the
    // exact recorded argument, but accept the alias only when both native APIs
    // agree on the complete canonical object (as in swift-dependency-replay).
    if(((d[0]>>16)&3)==2 && response.value!=m && !response.state && checkstate) {
        Response state=checkstate(0,m);
        if(state.value==response.value && !state.state) return NULL;
    }
    if(response.value!=m || response.state) return "exact-key dependency canonical identity differs";
    return NULL;
}

struct Definition { unsigned long id; const uintptr_t *metadata; const char *error; };
static struct Definition *definitions;
static size_t definition_count;
static struct Definition *definition(const char *text) {
    char *end=NULL; unsigned long id=strtoul(text,&end,10);
    if(!*text || *end) fail("invalid constructor identity");
    for(size_t i=0;i<definition_count;i++) if(definitions[i].id==id) return &definitions[i];
    return NULL;
}
static void save_definition(struct Definition row) {
    definitions=realloc(definitions,(definition_count+1)*sizeof(*definitions));
    if(!definitions) fail("allocation failed");
    definitions[definition_count++]=row;
    printf("{\"constructor\":%lu,\"metadata\":%llu",row.id,(unsigned long long)row.metadata);
    if(row.error) { printf(",\"error\":");string(row.error,strlen(row.error)); } puts("}");
}
static void unavailable(char *text,int bound_cache) {
    if(!bound_cache) fail("unavailable constructor needs a matching cache UUID");
    char *value=strchr(text,'\t'); if(!value) fail("unavailable constructor needs a signal"); *value++=0;
    if(definition(text)) fail("duplicate constructor identity");
    char *end=NULL; unsigned long signum=strtoul(value,&end,10);
    if(!*value || *end || !signum || signum>=64) fail("invalid native constructor signal");
    char *error=NULL;
    if(asprintf(&error,"native constructor terminated by signal %lu in a prior worker",signum)<0)
        fail("allocation failed");
    save_definition((struct Definition){strtoul(text,NULL,10),NULL,error});
}
static void construct_opaque(char *text,int bound_cache) {
    if(!bound_cache) fail("opaque constructor needs a matching cache UUID");
    char *fields[7];
    for(unsigned i=0;i<7;i++) if(!(fields[i]=strsep(&text,"\t"))) fail("incomplete opaque constructor");
    if(text || definition(fields[0])) fail("invalid opaque constructor identity");
    struct Definition row={strtoul(fields[0],NULL,10),NULL,NULL};
    printf("{\"constructor_begin\":%lu}\n",row.id);
    uintptr_t offset=strtoull(fields[1],NULL,16);
    uintptr_t scope=strtoull(fields[2],NULL,16);
    unsigned ordinal=(unsigned)strtoul(fields[3],NULL,10), expected=(unsigned)strtoul(fields[4],NULL,10);
    if(offset>=cache_end-cache_start || scope>=cache_end-cache_start || expected>64) fail("invalid opaque constructor extent");
    const void *descriptor=(const void*)(cache_start+offset), *arguments[64]={0};
    size_t count=0; char *save=NULL;
    if(strcmp(fields[5],"-")) for(char *part=strtok_r(fields[5],",",&save);part;part=strtok_r(NULL,",",&save)) {
        struct Definition *child=definition(part);
        if(!child || count>=expected) fail("opaque type argument missing or key too wide");
        arguments[count++]=child->metadata;
        if(child->error) row.error=child->error;
    }
    if(!getopaque || !conforms) row.error="opaque metadata runtime API unavailable";
    save=NULL;
    if(!row.error && strcmp(fields[6],"-")) for(char *part=strtok_r(fields[6],",",&save);part;part=strtok_r(NULL,",",&save)) {
        unsigned long long subject,protocol; size_t length;
        if(sscanf(part,"%llx:%zu:%llx",&subject,&length,&protocol)!=3 || count>=expected ||
           subject>=cache_end-cache_start || length>cache_end-cache_start-subject || protocol>=cache_end-cache_start)
            fail("invalid opaque protocol requirement");
        const void *type=resolve((const char*)(cache_start+subject),length,(const void*)(cache_start+scope),arguments);
        const void *witness=type?conforms(type,(const void*)(cache_start+protocol)):NULL;
        if(!witness) { row.error="opaque protocol requirement did not resolve"; break; }
        arguments[count++]=witness;
    }
    if(!row.error && count!=expected) fail("opaque constructor key width differs");
    if(!row.error) {
        Response result=getopaque(0,arguments,descriptor,ordinal);
        row.metadata=result.value;
        if(!result.value || result.state) row.error="opaque metadata is incomplete";
    }
    save_definition(row);
}
static void construct(int is_generic,char *text,int bound_cache) {
    if(!bound_cache) fail("constructor recipe needs a matching cache UUID");
    char *value=strchr(text,'\t'); if(!value) fail("constructor needs a value"); *value++=0;
    if(definition(text)) fail("duplicate constructor identity");
    struct Definition row={strtoul(text,NULL,10),NULL,NULL};
    printf("{\"constructor_begin\":%lu}\n",row.id);
    if(is_generic==2) {
        char *end=NULL; unsigned long long offset=strtoull(value,&end,16);
        if(!*value || *end || offset>=cache_end-cache_start)
            fail("constructor metadata reference outside shared cache");
        if(!cached(cache_start+offset) || !constructor_image_loaded(cache_start+offset))
            row.error="constructor metadata image is unavailable in this process";
        else {
            row.metadata=(const void*)(cache_start+offset);
            row.error=prepare_argument(row.metadata,0);
        }
    } else if(!is_generic) {
        row.metadata=resolve(value,strlen(value),NULL,NULL);
        if(!row.metadata) row.error="constructor type name did not resolve";
    } else {
        char *args=strchr(value,'\t'); if(!args) fail("generic constructor needs arguments"); *args++=0;
        char *end=NULL; unsigned long long offset=strtoull(value,&end,16);
        if(!*value || *end || offset>=cache_end-cache_start) fail("constructor descriptor outside shared cache");
        const uint32_t *d=(const void*)(cache_start+offset);
        if(!cached((uintptr_t)d) || !(d[0]&128) || ((d[0]&31)!=17 && (d[0]&31)!=18))
            row.error="constructor is not cached generic value metadata";
        else if(!constructor_image_loaded((uintptr_t)d))
            row.error="constructor descriptor image is unavailable in this process";
        const void *arguments[64]; size_t count=0;char *save=NULL;
        for(char *part=strtok_r(args,",",&save);part;part=strtok_r(NULL,",",&save)) {
            struct Definition *child=definition(part);
            if(!child || count==64) fail("constructor argument is missing or key is too wide");
            arguments[count++]=child->metadata;
            if(child->error) row.error=child->error;
        }
#ifdef SWIFT_WITNESS_GRAPH
        if(!row.error) row.error=swift_graph_generic_arguments(d,arguments,count,64);
#else
        const uint16_t *context=(const void*)(d+9);
        if(!row.error && (!count || context[0]!=count || context[2]!=count || (context[3]&~2u)))
            row.error="constructor key differs from type arguments";
#endif
        if(!row.error) {
            Response result=generic(0,arguments,d);
            row.metadata=result.value;
            if(!result.value || result.state) row.error="constructor metadata is incomplete";
        }
    }
    save_definition(row);
}

int main(void) {
    alarm(60); setvbuf(stdout,NULL,_IOLBF,0);
    size_t size=0;
    const void *(*range)(size_t*)=dlsym(RTLD_DEFAULT,"_dyld_get_shared_cache_range");
    if(!range) fail("shared cache range API unavailable");
    cache_start=(uintptr_t)range(&size); cache_end=cache_start+size;
    struct task_dyld_info ti={0}; mach_msg_type_number_t count=TASK_DYLD_INFO_COUNT;
    if(!size || task_info(mach_task_self(),TASK_DYLD_INFO,(task_info_t)&ti,&count)!=KERN_SUCCESS)
        fail("mapped cache identity unavailable");
    const struct dyld_all_image_infos *info=(const void*)ti.all_image_info_addr;
    uuid_string_t uuid; uuid_unparse_lower(info->sharedCacheUUID,uuid);
    printf("{\"schema\":2,\"cache_uuid\":\"%s\",\"base\":%llu,\"end\":%llu}\n",uuid,
           (unsigned long long)cache_start,(unsigned long long)cache_end);
    void *lib=dlopen("/usr/lib/swift/libswiftCore.dylib",RTLD_NOW|RTLD_LOCAL);
    if(!lib) fail(dlerror());
    resolve=dlsym(lib,"swift_getTypeByMangledNameInContext");
    getmetatype=dlsym(lib,"swift_getMetatypeMetadata");
    generic=dlsym(lib,"swift_getGenericMetadata"); getname=dlsym(lib,"swift_getMangledTypeName");
    checkstate=dlsym(lib,"swift_checkMetadataState");
    getcontext=dlsym(lib,"swift_getTypeContextDescriptor");
    getopaque=dlsym(lib,"swift_getOpaqueTypeMetadata");
    conforms=dlsym(lib,"swift_conformsToProtocol");
    if(!getmetatype || !resolve || !generic || !getname || !getcontext) fail("Swift runtime entry points unavailable");
#ifdef SWIFT_WITNESS_GRAPH
    if(swift_witness_graph_start()) fail("witness constructor recorder could not attach");
#endif
    int bound_cache=0;
    char *line=NULL; size_t capacity=0,index=0; ssize_t length;
    while((length=getline(&line,&capacity,stdin))!=-1) {
        alarm(60);
        if(length<3 || line[length-1]!='\n') fail("invalid recipe line");
        line[length-1]=0; char *owner=strchr(line,'\t');
        if(!owner) fail("recipe needs name and owner"); *owner++=0;
        if(!strcmp(line,"@cache")) {
            if(strcmp(owner,uuid)) fail("exact-key recipe belongs to a different shared cache");
            bound_cache=1; continue;
        }
        if(!strcmp(line,"@metadata")) {
            char *end=NULL; unsigned long long offset=strtoull(owner,&end,16);
            if(!bound_cache || !*owner || *end || offset>=cache_end-cache_start)
                fail("installed metadata needs a matching cache and valid offset");
            installed_metadata=realloc(installed_metadata,(installed_count+1)*sizeof(*installed_metadata));
            if(!installed_metadata) fail("allocation failed");
            installed_metadata[installed_count++]=cache_start+offset;
            continue;
        }
        if(!strcmp(line,"@load")) {
            if(!dlopen(owner,RTLD_NOW|RTLD_LOCAL)) fprintf(stderr,"preload %s: %s\n",owner,dlerror());
            continue;
        }
        if(!strcmp(line,"@type") || !strcmp(line,"@generic") || !strcmp(line,"@reference")) {
            construct(!strcmp(line,"@reference")?2:!strcmp(line,"@generic"),owner,bound_cache);
            continue;
        }
        if(!strcmp(line,"@unavailable")) {
            unavailable(owner,bound_cache);
            continue;
        }
        if(!strcmp(line,"@opaque")) {
            construct_opaque(owner,bound_cache);
            continue;
        }
        char *keys=strchr(owner,'\t');
        if(keys) *keys++=0;
        fprintf(stderr,"generate graph %zu %s\n",++index,line);
        const uintptr_t *m=NULL; const char *error=NULL;
        if(!dlopen(owner,RTLD_NOW|RTLD_LOCAL)) error="owner could not be loaded";
        else if(keys && keys[0]=='&') {
            struct Definition *node=definition(keys+1);
            if(!node) fail("root constructor is missing");
            m=node->metadata; error=node->error;
        }
        else if(keys) {
            if(!bound_cache) fail("exact-key recipe needs a matching cache UUID");
            const void *key[64]; size_t count=0; char *save=NULL;
            for(char *part=strtok_r(keys,",",&save);part;part=strtok_r(NULL,",",&save)) {
                char *end=NULL; unsigned long long offset=strtoull(part,&end,16);
                if(count==64 || !*part || *end || offset>=cache_end-cache_start)
                    fail("exact-key pointer outside shared cache");
                key[count++]=(const void*)(cache_start+offset);
            }
            if(count<2) fail("exact-key recipe needs descriptor and arguments");
            if(key[0]==(const void*)getmetatype) {
                if(count!=2) error="metatype key needs one instance type";
                else error=prepare_argument(key[1],0);
                if(!error) m=getmetatype(key[1]);
            } else {
                const uint32_t *descriptor=key[0];
                unsigned kind=descriptor[0]&31;
                if(!(descriptor[0]&128) || (kind!=17 && kind!=18)) error="exact-key root is not generic value metadata";
                const uint16_t *context=(const void*)(descriptor+9);
                if(!error && (context[0]>context[2] || context[2]!=count-1 || (context[3]&~2u)))
                    error="unsupported exact-key root context";
                for(unsigned i=0;!error && i<context[0];i++)
                    error=prepare_argument(key[1+i],0);
                if(!error) {
                    Response response=generic(0,key+1,key[0]);
                    m=response.value;
                    if(!m || response.state) error="exact-key metadata is incomplete";
                }
            }
        }
        else if(!(m=resolve(line,strlen(line),NULL,NULL))) error="type name did not resolve";
        printf("{\"root\":%zu,\"name\":",index); string(line,strlen(line));
        printf(",\"metadata\":%llu",(unsigned long long)m);
        if(error) { printf(",\"error\":"); string(error,strlen(error)); }
        puts("}");
        if(m && !error) capture(m,0);
    }
#ifdef SWIFT_WITNESS_GRAPH
    swift_witness_graph_finish(capture);
#endif
    if(getenv("SWIFT_GRAPH_IMAGE_HEADERS")) {
        // Optional own-process evidence for offline/native ABI fixtures. These
        // exact Mach-O headers let the normalizer retain image UUID/sections.
        for(uint32_t i=0;i<_dyld_image_count();i++) {
            const struct mach_header_64 *h=(const void*)_dyld_get_image_header(i);
            if((uintptr_t)h<cache_start || (uintptr_t)h>=cache_end || h->magic!=MH_MAGIC_64) continue;
            const char *path=_dyld_get_image_name(i);
            printf("{\"image_header\":");string(path,strlen(path));
            printf(",\"address\":%llu,\"slide\":%lld,\"data\":\"",(unsigned long long)h,(long long)_dyld_get_image_vmaddr_slide(i));
            const unsigned char *bytes=(const void*)h;
            for(size_t j=0;j<sizeof(*h)+h->sizeofcmds;j++) printf("%02x",bytes[j]);
            puts("\"}");
        }
    }
    puts("{\"complete\":true}"); free(line); free(visited); free(installed_metadata); free(definitions); return ferror(stdin)?2:0;
}
