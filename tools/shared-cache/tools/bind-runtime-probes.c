// Bind cache-derived instruction probes to this boot's mapping. Local Swift/ObjC
// symbols are absent from the laptop's DTrace symbol view, including their extents.
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld_images.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

static void fail(const char *s) { fprintf(stderr,"bind-runtime-probes: %s\n",s); exit(2); }
int main(int argc, char **argv) {
    if (argc<3 || argc>4) fail("usage: bind-runtime-probes TEMPLATE CACHE_UUID [PID]");
    mach_port_t task=mach_task_self();
    if (argc==4 && task_for_pid(mach_task_self(),atoi(argv[3]),&task)!=KERN_SUCCESS)
        fail("task_for_pid failed");
    struct task_dyld_info ti={0}; mach_msg_type_number_t count=TASK_DYLD_INFO_COUNT;
    if (task_info(task,TASK_DYLD_INFO,(task_info_t)&ti,&count)!=KERN_SUCCESS ||
        ti.all_image_info_format!=TASK_DYLD_ALL_IMAGE_INFO_64) fail("cannot read dyld info");
    struct dyld_all_image_infos info={0}; mach_vm_size_t got=0;
    size_t need=offsetof(struct dyld_all_image_infos,sharedCacheBaseAddress)+sizeof(info.sharedCacheBaseAddress);
    if (mach_vm_read_overwrite(task,ti.all_image_info_addr,need,(mach_vm_address_t)&info,&got)!=KERN_SUCCESS ||
        got!=need || info.version<15 || !info.sharedCacheBaseAddress) fail("cannot read cache mapping");
    if (task!=mach_task_self()) mach_port_deallocate(mach_task_self(),task);
    uuid_t expected;
    if (uuid_parse(argv[2],expected) || memcmp(expected,info.sharedCacheUUID,16))
        fail("template cache UUID differs from mapped cache");
    FILE *source=fopen(argv[1],"r"); if (!source) fail("cannot open template");
    printf("/* Bound cache %s slide 0x%llx */\n",argv[2],(unsigned long long)info.sharedCacheSlide);
    char *line=NULL; size_t size=0;
    while (getline(&line,&size,source)>=0) {
        char *p=line,*token;
        while ((token=strstr(p,"CACHEADDR_"))) {
            fwrite(p,1,(size_t)(token-p),stdout);
            char *end; unsigned long long address=strtoull(token+10,&end,16);
            if (end==token+10 || strncmp(end,"_END",4)) fail("invalid instruction address token");
            printf("%llx",address+info.sharedCacheSlide); p=end+4;
        }
        fputs(p,stdout);
    }
    if (ferror(source) || fflush(stdout)) fail("template I/O failed");
    free(line); fclose(source); return 0;
}
