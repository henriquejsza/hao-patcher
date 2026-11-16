#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct {const void *value; uintptr_t state;} Response;
typedef Response __attribute__((swiftcall)) Opaque(uintptr_t, const void *const *, const void *, unsigned);
typedef const void * __attribute__((swiftcall)) Resolve(const char *,size_t,const void*,const void*const*);
typedef const void * __attribute__((swiftcall)) Conforms(const void *, const void *);
int main(int argc,char **argv) {
 if(argc!=3) return 2;
 void *lib=dlopen(argv[1],RTLD_NOW|RTLD_GLOBAL),*swift=dlopen("/usr/lib/swift/libswiftCore.dylib",RTLD_NOW);
 if(!lib||!swift) return 3;
 Opaque *opaque=dlsym(swift,"swift_getOpaqueTypeMetadata");
 Resolve *resolve=dlsym(swift,"swift_getTypeByMangledNameInContext");
 Conforms *conforms=dlsym(swift,"swift_conformsToProtocol");
 const void *(*expected)(void)=dlsym(lib,"fixture_metadata");
 const void *descriptor=dlsym(lib,argv[2]),*protocol=dlsym(swift,"$sSHMp");
 if(!opaque||!resolve||!conforms||!expected||!descriptor||!protocol)return 4;
 const void *type=resolve("Su",2,NULL,NULL);
 const void *args[]={type,conforms(type,protocol)};
 if(!args[0]||!args[1])return 5;
 Response result=opaque(0,args,descriptor,0);
 printf("{\"same_metadata\":%s,\"state\":%llu}\n",result.value==expected()?"true":"false",(unsigned long long)result.state);
 return result.value!=expected()||result.state;
}
