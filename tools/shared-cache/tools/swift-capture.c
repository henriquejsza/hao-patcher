// Regenerate Optional metadata with the target runtime. Input is semantic names,
// never addresses from an older cache. Output is normalized by swift_metadata.py.
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>

typedef const void * __attribute__((swiftcall)) Resolve(const char *, size_t, const void *, const void *const *);
typedef struct { const void *value; uintptr_t state; } Response;
typedef Response __attribute__((swiftcall)) Generic(uintptr_t, const void *const *, const void *);
typedef void Inject(void *, unsigned, const void *);
typedef unsigned Tag(const void *, const void *);
typedef void *Copy(void *, const void *, const void *);
typedef void Destroy(void *, const void *);
static void fail(const char *message) { fprintf(stderr, "%s\n", message); exit(2); }
static void words(const uintptr_t *p, size_t n) {
    putchar('[');
    for (size_t i=0; i<n; ++i) printf("%s%llu", i?",":"", (unsigned long long)p[i]);
    putchar(']');
}
int main(void) {
    alarm(30); setvbuf(stdout, NULL, _IOLBF, 0);
    struct task_dyld_info ti={0}; mach_msg_type_number_t count=TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&ti, &count)!=KERN_SUCCESS ||
        ti.all_image_info_format!=TASK_DYLD_ALL_IMAGE_INFO_64) fail("cannot read mapped cache identity");
    const struct dyld_all_image_infos *info=(const void*)ti.all_image_info_addr;
    if (info->version<15 || !info->sharedCacheBaseAddress) fail("no mapped shared cache");
    uuid_string_t uuid; uuid_unparse_lower(info->sharedCacheUUID, uuid);
    printf("{\"schema\":1,\"cache_uuid\":\"%s\",\"base\":%llu}\n", uuid,
           (unsigned long long)info->sharedCacheBaseAddress);
    void *lib=dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_NOW|RTLD_LOCAL);
    if (!lib) fail(dlerror());
    Resolve *resolve=(Resolve*)dlsym(lib,"swift_getTypeByMangledNameInContext");
    Generic *generic=(Generic*)dlsym(lib,"swift_getGenericMetadata");
    if (!resolve || !generic) fail("Swift metadata entry points unavailable");
    const char controlName[]="s6UInt32VSg";
    const uintptr_t *control=resolve(controlName,sizeof(controlName)-1,NULL,NULL);
    if (!control || control[0]!=0x202) fail("Optional metadata ABI differs");
    const uint32_t *descriptor=(const void*)control[1];
    const unsigned char *pattern=(const unsigned char*)descriptor+32+(int32_t)descriptor[8];
    const uint32_t *p=(const void*)pattern; const uint16_t *extra=(const void*)(pattern+20);
    if (descriptor[0]!=0x800f2 || descriptor[5]!=1 || descriptor[6]!=1 || p[2]!=0x40400003 ||
        extra[0]!=1 || extra[1]!=1 || *(const uintptr_t*)(pattern+16+(int32_t)p[4]))
        fail("unsupported Optional allocation pattern");
    char *line=NULL; size_t capacity=0, index=0; ssize_t length;
    while ((length=getline(&line,&capacity,stdin))!=-1) {
        alarm(30);
        if (length>8192 || length<3 || line[length-1]!='\n') fail("invalid recipe line");
        line[length-1]=0; char *owner=strchr(line,'\t');
        if (!owner) fail("recipe needs name and owner"); *owner++=0;
        fprintf(stderr,"generate %zu %s\n",++index,line);
        if (!dlopen(owner,RTLD_NOW|RTLD_LOCAL)) fail(dlerror());
        const uintptr_t *metadata=resolve(line,strlen(line),NULL,NULL);
        if (!metadata || metadata[0]!=0x202 || metadata[1]!=(uintptr_t)descriptor)
            fail("recipe name did not resolve to Optional");
        const void *argument=(const void*)metadata[2]; Response again=generic(0,&argument,descriptor);
        if (again.value!=metadata || again.state) fail("metadata is incomplete or noncanonical");
        const uintptr_t *w=(const void*)metadata[-1]; uint32_t flags=(uint32_t)w[10];
        size_t alignment=(flags&255)+1, stride=w[9];
        if (metadata[-2] || metadata[3] || !(flags&0x200000) || (flags&0x800000) ||
            (alignment&(alignment-1)) || !stride || stride>65536 || w[8]>stride) {
            fprintf(stderr, "layout: prefix=%llu extra=%llu size=%llu stride=%llu flags=0x%x\n",
                    (unsigned long long)metadata[-2], (unsigned long long)metadata[3],
                    (unsigned long long)w[8], (unsigned long long)stride, flags);
            fail("unsupported Optional value layout");
        }
        void *a=NULL,*b=NULL; size_t align=alignment<8?8:alignment;
        if (posix_memalign(&a,align,stride) || posix_memalign(&b,align,stride)) fail("allocation failed");
        memset(a,0x55,stride); memset(b,0xaa,stride);
        ((Inject*)w[13])(a,1,metadata);
        if (((Tag*)w[11])(a,metadata)!=1 || ((Copy*)w[2])(b,a,metadata)!=b ||
            ((Tag*)w[11])(b,metadata)!=1) fail("Optional none copy failed");
        ((Destroy*)w[1])(b,metadata); ((Destroy*)w[1])(a,metadata); free(a); free(b);
        printf("{\"index\":%zu,\"metadata\":%llu,\"full_metadata\":",index,(unsigned long long)metadata);
        words(metadata-2,6); printf(",\"witness\":"); words(w,14);
        printf(",\"none_copy_destroy\":true}\n");
    }
    free(line); alarm(0); return ferror(stdin)?2:0;
}
