// A shared-cache reservation can also contain process-local Swift allocations.
// Require an actual file-backed section before serializing a cache-relative
// pointer.
#ifndef SSD_CACHE_ADDRESS_H
#define SSD_CACHE_ADDRESS_H
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <string.h>
static int file_backed_cache_pointer(uintptr_t p, uintptr_t cache_start,
                                     uintptr_t cache_end) {
  // The reserved cache range can contain Swift's process-local metadata pool.
  // dladdr also attributes that pool to an image. Require an actual section,
  // matching the host normalizer, rather than the reservation or dladdr alone.
  Dl_info image = {};
  if (p < cache_start || p >= cache_end || !dladdr((const void *)p, &image))
    return 0;
  const struct mach_header_64 *h =
      (const struct mach_header_64 *)image.dli_fbase;
  if (h->magic != MH_MAGIC_64)
    return 0;
  const struct load_command *lc = (const struct load_command *)(h + 1);
  uintptr_t slide = 0;
  for (unsigned i = 0; i < h->ncmds;
       i++, lc = (const struct load_command *)((const char *)lc + lc->cmdsize))
    if (lc->cmd == LC_SEGMENT_64) {
      const struct segment_command_64 *seg =
          (const struct segment_command_64 *)lc;
      if (!strcmp(seg->segname, "__TEXT"))
        slide = (uintptr_t)h - seg->vmaddr;
    }
  lc = (const struct load_command *)(h + 1);
  for (unsigned i = 0; i < h->ncmds;
       i++, lc = (const struct load_command *)((const char *)lc + lc->cmdsize))
    if (lc->cmd == LC_SEGMENT_64) {
      const struct segment_command_64 *seg =
          (const struct segment_command_64 *)lc;
      const struct section_64 *s = (const struct section_64 *)(seg + 1);
      for (unsigned j = 0; j < seg->nsects; j++)
        if (p >= s[j].addr + slide && p < s[j].addr + slide + s[j].size) {
          unsigned type = s[j].flags & SECTION_TYPE;
          return type != S_ZEROFILL && type != S_GB_ZEROFILL &&
                 type != S_THREAD_LOCAL_ZEROFILL;
        }
    }
  return 0;
}
#endif
