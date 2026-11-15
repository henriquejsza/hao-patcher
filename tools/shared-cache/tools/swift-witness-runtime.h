#ifndef SSD_SWIFT_WITNESS_RUNTIME_H
#define SSD_SWIFT_WITNESS_RUNTIME_H
#include <stdint.h>
#include <stddef.h>
typedef const void *WitnessOriginal(const void *, const void *, const void *const *);
typedef const void *WitnessLookup(const void *, const void *, size_t, const void **);
struct WitnessRuntime {
  const intptr_t *once;
  void (*initialize)(void);
  const uint32_t *mode;
  const void *table;
  WitnessLookup *lookup;
  WitnessOriginal *original;
};
extern struct WitnessRuntime hao_witness_runtime;
const void *hao_witness_lookup(const void *, const void *, const void *const *);
typedef const void *MetatypeOriginal(const void *);
struct MetatypeRuntime {
  const intptr_t *once;
  void (*initialize)(void);
  const uint32_t *mode;
  const void *table;
  WitnessLookup *lookup;
  const void *key;
  MetatypeOriginal *original;
};
extern struct MetatypeRuntime hao_metatype_runtime;
const void *hao_metatype_lookup(const void *);
struct MetadataShape {
  const void *descriptor;
  uint32_t types, count;
};
typedef const void *MetadataOriginal(const void *, const void *const *);
struct MetadataRuntime {
  const uint32_t *mode;
  const void *table;
  WitnessLookup *lookup;
  MetadataOriginal *original;
  const struct MetadataShape *shapes;
  size_t count;
};
extern struct MetadataRuntime hao_metadata_runtime;
const void *hao_metadata_lookup(const void *, const void *const *);
#endif
