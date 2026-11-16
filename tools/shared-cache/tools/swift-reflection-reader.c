// Thin client of SwiftRemoteMirror. Swift owns every Swift metadata/layout decode.
#include "SwiftRemoteMirror.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>
#include <unistd.h>
struct Reader {mach_port_t task;uintptr_t local_base,remote_base,size;};
static SwiftReflectionContextRef reflection;
static int read_into(struct Reader *r,uint64_t address,void *out,size_t size){
 mach_vm_size_t got=0;return mach_vm_read_overwrite(r->task,address,size,(mach_vm_address_t)out,&got)==KERN_SUCCESS && got==size;
}
static const void *read_bytes(void *ctx,swift_addr_t address,uint64_t size,void **free_ctx){
 *free_ctx=NULL;void *data=malloc(size?size:1);if(!data)return NULL;
 if(!read_into(ctx,address,data,size)){free(data);return NULL;}return data;
}
static void free_bytes(void *ctx,const void *bytes,void *free_ctx){(void)ctx;(void)free_ctx;free((void*)bytes);}
static uint64_t string_length(void *ctx,swift_addr_t address){
 uint64_t length=0;unsigned char bytes[256];
 while(length<1048576){size_t n=256-((address+length)%256);if(!read_into(ctx,address+length,bytes,n))return 0;
  for(size_t i=0;i<n;i++)if(!bytes[i])return length+i;length+=n;}return 0;
}
static swift_addr_t symbol_address(void *ctx,const char *name,uint64_t size){
 struct Reader *r=ctx;char *copy=malloc(size+1);if(!copy)return 0;memcpy(copy,name,size);copy[size]=0;
 void *p=dlsym(RTLD_DEFAULT,copy);
 if(!p)p=dlsym(RTLD_DEFAULT,copy[0]=='_'?copy+1:copy);
 if(!p)fprintf(stderr,"symbol unavailable: %s\n",copy);
 free(copy);uintptr_t address=(uintptr_t)p;
 return address>=r->local_base && address<r->local_base+r->size?address-r->local_base+r->remote_base:0;
}
static void string(const char *s){
 if(!s){printf("null");return;}putchar('"');
 for(const unsigned char *p=(const void*)s;*p;p++){
  if(*p=='"'||*p=='\\')printf("\\%c",*p);else if(*p<32)printf("\\u%04x",*p);else putchar(*p);
 }putchar('"');
}
// Mach-O identity is transport data; Swift layouts remain owned by Remote Mirror.
static void image_record(struct Reader *r, const struct dyld_image_info *image, int added){
 uintptr_t address=(uintptr_t)image->imageLoadAddress;
 struct mach_header_64 header;
 if(!read_into(r,address,&header,sizeof(header)) || header.magic!=MH_MAGIC_64)return;
 unsigned char *commands=malloc(header.sizeofcmds);
 if(!commands || !read_into(r,address+sizeof(header),commands,header.sizeofcmds)){free(commands);return;}
 uuid_t uuid={0};uintptr_t slide=0;
 for(unsigned offset=0;offset+sizeof(struct load_command)<=header.sizeofcmds;){
  struct load_command *lc=(void*)(commands+offset);
  if(lc->cmdsize<sizeof(*lc)||lc->cmdsize>header.sizeofcmds-offset)break;
  if(lc->cmd==LC_UUID && lc->cmdsize>=sizeof(struct uuid_command))memcpy(uuid,((struct uuid_command*)lc)->uuid,16);
  if(lc->cmd==LC_SEGMENT_64 && lc->cmdsize>=sizeof(struct segment_command_64)){
   struct segment_command_64 *seg=(void*)lc;if(!strcmp(seg->segname,"__TEXT"))slide=address-seg->vmaddr;
  }
  offset+=lc->cmdsize;
 }
 uint64_t length=string_length(r,(uintptr_t)image->imageFilePath);char *path=calloc(length+1,1);
 if(path && length)read_into(r,(uintptr_t)image->imageFilePath,path,length);
 uuid_string_t uuid_text;uuid_unparse_lower(uuid,uuid_text);
 printf("{\"image\":%llu,\"path\":",(unsigned long long)address);string(path);free(path);
 printf(",\"uuid\":\"%s\",\"reflection_added\":%s,\"segments\":[",uuid_text,added?"true":"false");
 unsigned count=0;
 for(unsigned offset=0;offset+sizeof(struct load_command)<=header.sizeofcmds;){
  struct load_command *lc=(void*)(commands+offset);
  if(lc->cmdsize<sizeof(*lc)||lc->cmdsize>header.sizeofcmds-offset)break;
  if(lc->cmd==LC_SEGMENT_64 && lc->cmdsize>=sizeof(struct segment_command_64)){
   struct segment_command_64 *seg=(void*)lc;
   if(seg->filesize){printf("%s{\"start\":%llu,\"size\":%llu,\"name\":",count++?",":"",(unsigned long long)(seg->vmaddr+slide),(unsigned long long)seg->filesize);
    char name[17]={0};memcpy(name,seg->segname,16);string(name);putchar('}');}
  }
  offset+=lc->cmdsize;
 }
 puts("]}");free(commands);
}
#define CAPACITY (1u<<19)
static swift_typeref_t *queue,*keys;
static unsigned *ids,used,capacity;
static unsigned intern(swift_typeref_t tr){
 if(!tr)return 0;unsigned slot=(unsigned)((tr>>4)*11400714819323198485ull)&(CAPACITY-1);
 while(keys[slot]&&keys[slot]!=tr)slot=(slot+1)&(CAPACITY-1);
 if(keys[slot])return ids[slot];
 if(used>=CAPACITY/2){fprintf(stderr,"reflection graph exceeds table capacity\n");exit(2);}
 if(used==capacity){capacity=capacity?capacity*2:1024;queue=realloc(queue,capacity*sizeof(*queue));if(!queue)exit(2);}
 keys[slot]=tr;ids[slot]=++used;queue[used-1]=tr;return used;
}
static void conformance(swift_reflection_ptr_t type,swift_reflection_ptr_t proto,void *ctx){
 (void)ctx;swift_typeref_t tr=swift_reflection_typeRefForMetadata(reflection,type);
 char *name=swift_reflection_copyDemangledNameForProtocolDescriptor(reflection,proto);
 printf("{\"conformance\":true,\"metadata\":%llu,\"type\":%u,\"protocol\":%llu,\"protocol_name\":",(unsigned long long)type,intern(tr),(unsigned long long)proto);string(name);puts("}");free(name);
}
int main(int argc,char **argv){
 if(argc!=2)return 2;char *end;long pid=strtol(argv[1],&end,10);if(*end||pid<=1||pid>INT32_MAX)return 2;
 struct Reader reader={0};kern_return_t rc=KERN_SUCCESS;
 if(pid==getpid())reader.task=mach_task_self();else rc=task_for_pid(mach_task_self(),(int)pid,&reader.task);
 if(rc!=KERN_SUCCESS){fprintf(stderr,"task_for_pid: %s\n",mach_error_string(rc));return 1;}
 struct task_dyld_info ti={0};mach_msg_type_number_t count=TASK_DYLD_INFO_COUNT;
 struct dyld_all_image_infos info={0};size_t extent=offsetof(struct dyld_all_image_infos,sharedCacheBaseAddress)+sizeof(uintptr_t);
 if(task_info(reader.task,TASK_DYLD_INFO,(task_info_t)&ti,&count)!=KERN_SUCCESS||ti.all_image_info_format!=TASK_DYLD_ALL_IMAGE_INFO_64||ti.all_image_info_size<extent||!read_into(&reader,ti.all_image_info_addr,&info,extent))return 1;
 const void *(*range)(size_t*)=dlsym(RTLD_DEFAULT,"_dyld_get_shared_cache_range");
 _Bool (*uuidfn)(uuid_t)=dlsym(RTLD_DEFAULT,"_dyld_get_shared_cache_uuid");uuid_t local_uuid;
 if(!range||!uuidfn||!uuidfn(local_uuid)||memcmp(local_uuid,info.sharedCacheUUID,16))return 1;
 size_t range_size;reader.local_base=(uintptr_t)range(&range_size);reader.size=range_size;reader.remote_base=info.sharedCacheBaseAddress;
 dlopen("/usr/lib/swift/libswiftCore.dylib",RTLD_NOW|RTLD_GLOBAL);
 reflection=swift_reflection_createReflectionContext(&reader,8,free_bytes,read_bytes,string_length,symbol_address);
 if(!reflection)return 1;
 struct dyld_image_info *images=malloc(info.infoArrayCount*sizeof(*images));
 if(!images||!read_into(&reader,(uintptr_t)info.infoArray,images,info.infoArrayCount*sizeof(*images)))return 1;
 unsigned without_reflection=0;for(unsigned i=0;i<info.infoArrayCount;i++){
  int added=swift_reflection_addImage(reflection,(uintptr_t)images[i].imageLoadAddress);
  if(!added)without_reflection++;image_record(&reader,&images[i],added);
 }
 free(images);keys=calloc(CAPACITY,sizeof(*keys));ids=calloc(CAPACITY,sizeof(*ids));if(!keys||!ids)return 1;
 setvbuf(stdout,NULL,_IOLBF,0);uuid_string_t uuid;uuid_unparse_lower(info.sharedCacheUUID,uuid);
 printf("{\"pid\":%ld,\"cache_uuid\":\"%s\",\"cache_slide\":%llu,\"library_version\":%u,\"metadata_version\":%u,\"images\":%u,\"images_without_reflection\":%u}\n",pid,uuid,(unsigned long long)info.sharedCacheSlide,swift_reflection_libraryVersion,swift_reflection_getSupportedMetadataVersion(),info.infoArrayCount,without_reflection);
 unsigned long long address;unsigned roots=0;
 while(scanf("%llx",&address)==1){
  swift_typeref_t tr=swift_reflection_typeRefForMetadata(reflection,address);unsigned id=intern(tr);
  swift_typeinfo_t layout=swift_reflection_infoForMetadata(reflection,address);
  printf("{\"root\":%u,\"metadata\":%llu,\"type\":%u,\"descriptor\":%llu,\"instance_kind\":%u,\"instance_size\":%u,\"instance_fields\":[",++roots,address,id,(unsigned long long)swift_reflection_metadataNominalTypeDescriptor(reflection,address),layout.Kind,layout.Size);
  if(layout.Kind==SWIFT_CLASS_INSTANCE || layout.Kind==SWIFT_CLOSURE_CONTEXT)
   for(unsigned j=0;j<layout.NumFields;j++){
    swift_childinfo_t child=swift_reflection_childOfMetadata(reflection,address,j);
    printf("%s{\"name\":",j?",":"");string(child.Name);printf(",\"offset\":%u,\"kind\":%u,\"type\":%u}",child.Offset,child.Kind,intern(child.TR));
   }
  puts("]}");
 }
 const char *error=swift_reflection_iterateConformanceCache(reflection,conformance,NULL);
 if(error){printf("{\"conformance_error\":");string(error);puts("}");}
 for(unsigned index=0;index<used;index++){
  swift_typeref_t tr=queue[index];char *name=swift_reflection_copyNameForTypeRef(reflection,tr,true);
  swift_typeinfo_t layout=swift_reflection_infoForTypeRef(reflection,tr);
  printf("{\"node\":%u,\"name\":",index+1);string(name);free(name);
  printf(",\"kind\":%u,\"size\":%u,\"alignment\":%u,\"stride\":%u,\"field_count\":%u,\"arguments\":[",layout.Kind,layout.Size,layout.Alignment,layout.Stride,layout.NumFields);
  unsigned args=swift_reflection_genericArgumentCountOfTypeRef(tr);
  for(unsigned j=0;j<args;j++)printf("%s%u",j?",":"",intern(swift_reflection_genericArgumentOfTypeRef(tr,j)));
  printf("],\"fields\":[");unsigned fields=layout.Kind==SWIFT_ARRAY && layout.NumFields?1:layout.NumFields;
  for(unsigned j=0;j<fields;j++){swift_childinfo_t child=swift_reflection_childOfTypeRef(reflection,tr,j);
   printf("%s{\"name\":",j?",":"");string(child.Name);printf(",\"offset\":%u,\"kind\":%u,\"type\":%u}",child.Offset,child.Kind,intern(child.TR));}
  puts("]}");
 }
 if(!feof(stdin)){fprintf(stderr,"invalid metadata address input\n");return 2;}
 printf("{\"complete\":true,\"roots\":%u,\"nodes\":%u}\n",roots,used);
 swift_reflection_destroyReflectionContext(reflection);mach_port_deallocate(mach_task_self(),reader.task);free(keys);free(ids);free(queue);return 0;
}
