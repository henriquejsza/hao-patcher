#ifndef SSD_WITNESS_RUNTIME_H
#define SSD_WITNESS_RUNTIME_H
#include "frida-gum.h"
#include <cstring>
struct WitnessImplementation {
  gpointer address;
  unsigned count;
};
static gboolean witness_symbol(const GumSymbolDetails *symbol, gpointer opaque) {
  auto result = static_cast<WitnessImplementation *>(opaque);
  // This ABI function receives both exported and ordinary conformance requests.
  const char *name = "_ZN5swift16_getWitnessTableEPKNS_35TargetProtocolConformanceDescriptorINS_9InProcessEEEPKNS_14TargetMetadataIS1_EEPKPKv";
  if (!std::strcmp(symbol->name, name)) {
    result->address = (gpointer)symbol->address;
    result->count++;
  }
  return TRUE;
}
static gpointer witness_implementation(gpointer fallback, bool *internal) {
  auto module = gum_process_find_module_by_name("libswiftCore.dylib");
  if (!module) return nullptr;
  WitnessImplementation result = {};
  gum_module_enumerate_symbols(module, witness_symbol, &result);
  g_object_unref(module);
  *internal = result.count == 1;
  return result.count > 1 ? nullptr : result.count ? result.address : fallback;
}
#endif
