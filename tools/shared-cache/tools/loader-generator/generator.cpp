// Host-only offline serialization harness; never runs target code.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <map>
#include <string>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "Allocator.h"
#include "DyldSharedCache.h"
#include "DyldProcessConfig.h"
#include "DyldRuntimeState.h"
#include "DyldDelegates.h"
#include "JustInTimeLoader.h"
#include "PrebuiltLoader.h"
#include "MachOLayout.h"
#include "UnsafeHeader.h"
using namespace dyld4;
using namespace dyld3;

// Unlike a source-only builder, this harness owns a real cache path trie.
static const DyldSharedCache* offlineCache = nullptr;
bool dyldOfflineCacheIndexOfPath(const char* path, uint32_t& index) {
    assert(offlineCache && path);
    return offlineCache->hasImagePath(path, index);
}
const char* dyldOfflineCachePath(uint32_t index) {
    assert(offlineCache && index < offlineCache->imagesCount());
    return offlineCache->getIndexedImagePath(index);
}


struct ImageLayout {
    std::vector<mach_o::SegmentLayout> segments;
    mach_o::LinkeditLayout linkedit;
    std::unique_ptr<mach_o::Layout> layout;
};

// Offline VM-layout view. ARM host pages are 16K, while these x86 cache
// mappings can be only 4K aligned. Retain direct file mappings where possible;
// copy only the unaligned mappings into private anonymous host pages.
// dyld-1378's header ends at 552; 27 (26B131) appends 16 bytes (mappings at 568). Fields before 552 are unchanged.
static bool headerSizeKnown(uint32_t mappingOffset) { return mappingOffset == 552 || mappingOffset == 568; }

static std::vector<const DyldSharedCache*> mapOffline(const char* path) {
    auto headerOf = [](const char* file, uint8_t bytes[4096], struct stat& st) {
        int fd = ::open(file, O_RDONLY);
        if (fd < 0 || ::fstat(fd, &st) || ::pread(fd, bytes, 4096, 0) != 4096) {
            if (fd >= 0) ::close(fd);
            return -1;
        }
        return fd;
    };
    uint8_t first[4096];
    struct stat st;
    int initial = headerOf(path, first, st);
    if (initial < 0) return {};
    ::close(initial);
    const auto* header = (const dyld_cache_header*)first;
    if (memcmp(header->magic, "dyld_v1  x86_64", 15) || !headerSizeKnown(header->mappingOffset) || !header->mappingCount || header->mappingCount > 8) return {};
    const auto* maps = (const dyld_cache_mapping_info*)(first + header->mappingOffset);
    uint64_t base = maps[0].address, size = header->sharedRegionSize;
    size_t page = (size_t)::sysconf(_SC_PAGESIZE);
    if (!size || size % page) return {};
    auto* buffer = (uint8_t*)::mmap(nullptr, size, PROT_NONE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (buffer == MAP_FAILED) return {};
    uint64_t mapped = 0, copied = 0, copiedBytes = 0;
    auto mapFile = [&](const char* file) -> const DyldSharedCache* {
        uint8_t raw[4096];
        struct stat stat;
        int fd = headerOf(file, raw, stat);
        if (fd < 0) return nullptr;
        const auto* h = (const dyld_cache_header*)raw;
        if (memcmp(h->magic, "dyld_v1  x86_64", 15) || !headerSizeKnown(h->mappingOffset) || !h->mappingCount || h->mappingCount > 8) { ::close(fd); return nullptr; }
        const auto* mappings = (const dyld_cache_mapping_info*)(raw + h->mappingOffset);
        for (uint32_t i = 0; i < h->mappingCount; ++i) {
            const auto& mapping = mappings[i];
            if (mapping.address < base || mapping.address - base > size || mapping.size > size - (mapping.address - base) ||
                mapping.fileOffset > (uint64_t)stat.st_size || mapping.size > (uint64_t)stat.st_size - mapping.fileOffset) { ::close(fd); return nullptr; }
            uint8_t* destination = buffer + mapping.address - base;
            if (((uintptr_t)destination % page) == 0 && mapping.fileOffset % page == 0 && mapping.size % page == 0) {
                if (::mmap(destination, mapping.size, PROT_READ, MAP_FIXED|MAP_PRIVATE, fd, mapping.fileOffset) == MAP_FAILED) { ::close(fd); return nullptr; }
                ++mapped;
            } else {
                uintptr_t start = (uintptr_t)destination & ~(page - 1);
                uintptr_t end = ((uintptr_t)destination + mapping.size + page - 1) & ~(page - 1);
                if (::mprotect((void*)start, end - start, PROT_READ|PROT_WRITE)) { ::close(fd); return nullptr; }
                uint64_t position = 0;
                while (position < mapping.size) {
                    size_t chunk = (size_t)std::min<uint64_t>(mapping.size - position, 16 * 1024 * 1024);
                    ssize_t got = ::pread(fd, destination + position, chunk, mapping.fileOffset + position);
                    if (got <= 0) { ::close(fd); return nullptr; }
                    position += (uint64_t)got;
                }
                if (::mprotect((void*)start, end - start, PROT_READ)) { ::close(fd); return nullptr; }
                ++copied; copiedBytes += mapping.size;
            }
        }
        ::close(fd);
        return (const DyldSharedCache*)(buffer + mappings[0].address - base);
    };
    const auto* main = mapFile(path);
    if (!main) return {};
    std::vector<const DyldSharedCache*> result{main};
    const auto* entries = (const dyld_subcache_entry*)(buffer + main->header.subCacheArrayOffset);
    for (uint32_t i = 0; i < main->header.subCacheArrayCount; ++i) {
        if (strnlen(entries[i].fileSuffix, 32) >= 32) return {};
        std::string file = std::string(path) + entries[i].fileSuffix;
        const auto* subcache = mapFile(file.c_str());
        if (!subcache || memcmp(subcache->header.uuid, entries[i].uuid, 16) ||
            subcache->unslidLoadAddress() - base != entries[i].cacheVMOffset) return {};
        result.push_back(subcache);
    }
    printf("offline_mapper files=%zu direct_mappings=%llu copied_mappings=%llu copied_bytes=%llu host_page=%zu\n", result.size(), mapped, copied, copiedBytes, page);
    return result;
}

int main(int argc, char** argv) {
    if (argc != 10 && argc != 11) { fprintf(stderr, "usage: generator CACHE EXECUTABLE VIRTUAL_PATH OUTPUT cached|program|program-batch IMAGE_COUNT FILE_COUNT ROOT_MAP CACHED_SET_OR_DASH [BATCH_TSV]\n"); return 2; }
    const char* cachePath = argv[1];
    const char* executablePath = argv[2];
    const char* virtualPath = argv[3];
    const char* outputPath = argv[4];
    bool cachedMode = strcmp(argv[5], "cached") == 0;
    bool batchMode = strcmp(argv[5], "program-batch") == 0;
    if ((!cachedMode && !batchMode && strcmp(argv[5], "program") != 0) || (batchMode != (argc == 11))) return 2;
    char* numberEnd = nullptr;
    unsigned long expectedImages = strtoul(argv[6], &numberEnd, 10);
    if (*numberEnd || expectedImages == 0 || expectedImages >= 0x7fff) return 2;
    unsigned long expectedFiles = strtoul(argv[7], &numberEnd, 10);
    if (*numberEnd || expectedFiles == 0 || expectedFiles > 64) return 2;
    if (virtualPath[0] != '/') return 2;
    std::ifstream stream(executablePath, std::ios::binary);
    std::vector<char> bytes((std::istreambuf_iterator<char>(stream)), {});
    if (bytes.size() < 32) return 2;
    uint64_t selectedSliceOffset = 0, selectedSliceSize = 0;
    Diagnostics sliceDiag;
    const auto* mainMF = MachOFile::compatibleSlice(sliceDiag, selectedSliceOffset, selectedSliceSize, bytes.data(), bytes.size(),
        virtualPath, mach_o::Platform::macOS, true, mach_o::GradedArchitectures::forName("x86_64"), false);
    if (!mainMF || sliceDiag.hasError()) { fprintf(stderr,"invalid x86 executable slice\n"); return 2; }
    if (mainMF->magic != MH_MAGIC_64 || mainMF->cputype != CPU_TYPE_X86_64 || mainMF->filetype != MH_EXECUTE) return 2;
    const auto* mainHeader = (const mach_o::UnsafeHeader*)mainMF;
    if (auto error = mainHeader->valid(selectedSliceSize)) { fprintf(stderr,"invalid executable: %s\n",error.message()); return 2; }
    auto caches = mapOffline(cachePath);
    if (caches.size() != expectedFiles || caches.front()->imagesCount() != expectedImages) {
        fprintf(stderr,"required cache family incomplete: %zu files (expected %lu), %u images (expected %lu)\n", caches.size(), expectedFiles,
                caches.empty() ? 0u : caches.front()->imagesCount(), expectedImages);
        return 2;
    }
    const auto* cache = caches.front();
    std::vector<char> cachedSetBytes;
    const PrebuiltLoaderSet* cachedSet = nullptr;
    if (!cachedMode) {
        if (strcmp(argv[9], "-") == 0) cachedSet = cache->dylibsLoaderSet();
        else {
            std::ifstream input(argv[9], std::ios::binary);
            cachedSetBytes.assign((std::istreambuf_iterator<char>(input)), {});
            if (cachedSetBytes.size() < 80) return 2;
            cachedSet = (const PrebuiltLoaderSet*)cachedSetBytes.data();
            if (cachedSet->size() != cachedSetBytes.size()) return 2;
        }
    }
    if (!cachedMode && (cachedSet == nullptr || !cachedSet->hasValidMagic() || ((const uint32_t*)cachedSet)[1] != 0x9593b355 || cachedSet->loaderCount() != cache->imagesCount())) {
        fprintf(stderr,"unsupported cached loader schema\n"); return 2;
    }
    const uint32_t imageCount = cache->imagesCount();
    offlineCache = cache;
    for (uint32_t i = 0; i < imageCount; ++i) {
        uint32_t found = UINT32_MAX;
        const char* path = dyldOfflineCachePath(i);
        if (!path || !dyldOfflineCacheIndexOfPath(path, found) || found != i) {
            fprintf(stderr, "cache canonical path/index roundtrip failed\n"); return 2;
        }
    }

    const uint64_t cacheBase = cache->unslidLoadAddress();
    auto mappedAddress = [=](uint64_t address) { return (const uint8_t*)cache + (address - cacheBase); };
    std::vector<ImageLayout> imageLayouts(imageCount);
    auto& alloc = lsl::MemoryManager::memoryManager().defaultAllocator();
    lsl::Vector<ProcessConfig::DyldCache::CacheDylib> dylibs(alloc);
    for (uint32_t index = 0; index < imageCount; ++index) {
        const auto* mf = (const MachOFile*)cache->getIndexedImageEntry(index);
        const auto* header = (const mach_o::UnsafeHeader*)mf;
        auto& holder = imageLayouts[index];
        auto* holderPtr = &holder;
        __block uint64_t linkeditVM = 0, linkeditFile = 0;
        header->forEachSegment(^(const mach_o::UnsafeHeader::SegmentInfo& info, bool& stop) {
            mach_o::SegmentLayout segment;
            segment.vmAddr = info.vmaddr;
            segment.vmSize = info.vmsize;
            segment.fileOffset = info.fileOffset;
            segment.fileSize = info.fileSize;
            segment.protections = info.initProt;
            segment.buffer = mappedAddress(info.vmaddr);
            if (info.segmentName == "__TEXT") segment.kind = mach_o::SegmentLayout::Kind::text;
            if (info.segmentName == "__LINKEDIT") {
                segment.kind = mach_o::SegmentLayout::Kind::linkedit;
                linkeditVM = info.vmaddr; linkeditFile = info.fileOffset;
            }
            holderPtr->segments.push_back(segment);
        });
        const uint8_t* command = (const uint8_t*)mf + 32;
        for (uint32_t i = 0; i < mf->ncmds; ++i) {
            const auto* lc = (const load_command*)command;
            if (lc->cmd == LC_DYLD_EXPORTS_TRIE || lc->cmd == LC_FUNCTION_VARIANTS) {
                const auto* data = (const linkedit_data_command*)command;
                auto& field = lc->cmd == LC_DYLD_EXPORTS_TRIE ? holder.linkedit.exportsTrie : holder.linkedit.functionVariants;
                field.buffer = mappedAddress(linkeditVM + data->dataoff - linkeditFile);
                field.bufferSize = data->datasize;
                field.hasLinkedit = true;
            }
            if (lc->cmd == LC_DYLD_INFO || lc->cmd == LC_DYLD_INFO_ONLY) {
                const auto* info = (const dyld_info_command*)command;
                if (info->export_size) {
                    holder.linkedit.exportsTrie.buffer = mappedAddress(linkeditVM + info->export_off - linkeditFile);
                    holder.linkedit.exportsTrie.bufferSize = info->export_size;
                    holder.linkedit.exportsTrie.hasLinkedit = true;
                }
            }
            command += lc->cmdsize;
        }
        holder.layout = std::make_unique<mach_o::Layout>(mf, holder.segments, holder.linkedit);
        ProcessConfig::DyldCache::CacheDylib dylib;
        dylib.mf = mf;
        dylib.layout = holder.layout.get();
        dylibs.push_back(dylib);
    }
    SyscallDelegate delegate;
    delegate._gradedArchs = &mach_o::GradedArchitectures::forName("x86_64");
    std::map<std::string, std::span<const char>> rootFiles;
    std::ifstream rootMap(argv[8]);
    if (!rootMap) { fprintf(stderr,"explicit root map is required\n"); return 2; }
    std::string line;
    while (std::getline(rootMap, line)) {
        auto tab = line.find('\t');
        if (tab == std::string::npos || line[0] != '/') return 2;
        auto path = line.substr(0, tab);
        auto physical = line.substr(tab + 1);
        if (rootFiles.count(path)) return 2;
        int fd = open(physical.c_str(), O_RDONLY);
        struct stat st;
        if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0) {
            if (fd >= 0) close(fd);
            fprintf(stderr,"missing explicit root file: %s\n",path.c_str()); return 2;
        }
        void* buffer = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (buffer == MAP_FAILED) return 2;
        rootFiles[path] = std::span<const char>((const char*)buffer, st.st_size);
    }
    for (const auto& file : rootFiles) delegate._mappedOtherDylibs[file.first] = {file.second.data(), file.second.size()};
    if (!delegate._mappedOtherDylibs.count(virtualPath)) { fprintf(stderr,"main executable is not in root map\n"); return 2; }
    auto mappedMain = rootFiles.at(virtualPath);
    if (mappedMain.size() != bytes.size() || memcmp(mappedMain.data(), bytes.data(), bytes.size())) { fprintf(stderr,"main input differs from explicit root mapping\n"); return 2; }
    // Fork only host serializer workers after the immutable cache/root inputs
    // are mapped. Every child constructs fresh ProcessConfig/RuntimeState.
    std::vector<std::vector<std::string>> batchRows;
    if (batchMode) {
        std::ifstream batch(argv[10]);
        if (!batch) return 2;
        while (std::getline(batch, line)) {
            auto first = line.find('\t'), second = line.find('\t', first == std::string::npos ? 0 : first + 1);
            if (first == std::string::npos || second == std::string::npos || line.find('\t', second + 1) != std::string::npos) return 2;
            batchRows.push_back({line.substr(0, first), line.substr(first + 1, second - first - 1), line.substr(second + 1)});
            if (!rootFiles.count(batchRows.back()[0])) return 2;
        }
        if (batchRows.empty()) return 2;
        unsigned live = 0, failures = 0;
        bool child = false;
        auto reap = [&]() {
            int status = 0;
            if (wait(&status) < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) ++failures;
            --live;
        };
        for (const auto& row : batchRows) {
            if (live == 4) reap();
            pid_t pid = fork();
            if (pid < 0) { ++failures; continue; }
            if (pid == 0) {
                child = true;
                virtualPath = row[0].c_str(); outputPath = row[1].c_str();
                int log = open(row[2].c_str(), O_WRONLY|O_CREAT|O_EXCL, 0600);
                if (log < 0 || dup2(log, STDOUT_FILENO) < 0 || dup2(log, STDERR_FILENO) < 0) return 2;
                close(log);
                auto input = rootFiles.at(virtualPath);
                bytes.assign(input.begin(), input.end());
                Diagnostics localDiag;
                mainMF = MachOFile::compatibleSlice(localDiag, selectedSliceOffset, selectedSliceSize, bytes.data(), bytes.size(),
                    virtualPath, mach_o::Platform::macOS, true, mach_o::GradedArchitectures::forName("x86_64"), false);
                if (!mainMF || localDiag.hasError() || mainMF->filetype != MH_EXECUTE) return 2;
                if (auto error = ((const mach_o::UnsafeHeader*)mainMF)->valid(selectedSliceSize)) return 2;
                break;
            }
            ++live;
        }
        if (!child) {
            while (live) reap();
            printf("batch programs=%zu failures=%u\n", batchRows.size(), failures);
            return failures ? 2 : 0;
        }
    }
    KernelArgs kernArgs(mainMF, {virtualPath}, {}, {});
    ProcessConfig config(&kernArgs, delegate, alloc);
    RuntimeLocks locks;
    RuntimeState state(config, locks, alloc);
    config.reset(mainMF, virtualPath, selectedSliceSize, nullptr);
    config.dyldCache.cacheBuilderDylibs = &dylibs;
    config.dyldCache.dylibCount = imageCount;
    config.dyldCache.unslidLoadAddress = cacheBase;
    config.dyldCache.dylibsExpectedOnDisk = false;
    config.dyldCache.development = cache->header.cacheType == kDyldSharedCacheTypeDevelopment ||
        (cache->header.cacheType == kDyldSharedCacheTypeUniversal && cache->header.cacheSubType == kDyldSharedCacheTypeDevelopment);
    config.dyldCache.objcClassHashTable = cache->objcClassHashTable();
    config.dyldCache.objcSelectorHashTable = cache->objcSelectorHashTable();
    config.dyldCache.objcProtocolHashTable = cache->objcProtocolHashTable();
    config.dyldCache.objcHeaderInfoRO = cache->objcHeaderInfoRO();
    config.dyldCache.objcHeaderInfoRW = cache->objcHeaderInfoRW();
    config.dyldCache.objcHeaderInfoROUnslidVMAddr = cacheBase + (uint64_t)cache->objcHeaderInfoRO() - (uint64_t)cache;
    const void* objcPointers = cache->objcOptPtrs();
    if (!objcPointers) { fprintf(stderr,"missing ObjC protocol-class pointer\n"); return 2; }
    uint64_t protocolRaw;
    memcpy(&protocolRaw, objcPointers, 8);
    auto converter = cache->makeVMAddrConverter(false);
    if (converter.sharedCacheChainedPointerFormat != MachOAnalyzer::VMAddrConverter::SharedCacheFormat::v2_x86_64_tbi || converter.preferredLoadAddress != cacheBase) {
        fprintf(stderr,"unsupported protocol-class pointer encoding\n"); return 2;
    }
    const uint64_t protocolOffset = protocolRaw & ~UINT64_C(0x00FFFF0000000000);
    if (!protocolOffset) { fprintf(stderr,"null protocol-class pointer\n"); return 2; }
    config.dyldCache.objcProtocolClassCacheOffset = protocolOffset;
    if (cachedMode) {
        config.dyldCache.patchTable = PatchTable(cache->patchTable(), cache->header.patchInfoAddr);
        std::vector<const Loader*> jit;
        jit.reserve(imageCount);
        for (uint32_t index = 0; index < imageCount; ++index) {
            const char* path = cache->getIndexedImagePath(index);
            bool twin = false;
            uint32_t twinIndex = 0;
            if (strncmp(path, "/System/iOSSupport/", 19) == 0)
                twin = cache->hasImagePath(path + 18, twinIndex);
            jit.push_back(JustInTimeLoader::makeJustInTimeLoaderDyldCache(state, dylibs.at(index).mf, path, index,
                          FileID::none(), twin, twinIndex, imageLayouts[index].layout.get()));
        }
        RuntimeState* cacheState = &state;
        const auto* jitArray = &jit;
        Loader::LoadOptions options;
        options.staticLinkage = true;
        options.launching = true;
        options.canBeDylib = true;
        options.finder = ^(Diagnostics& diag, mach_o::Platform platform, const char* path, const Loader::LoadOptions& inner) {
            uint32_t index;
            if (cache->hasImagePath(path, index)) return (*jitArray)[index];
            if (!inner.canBeMissing) diag.error("required cached dependency missing: %s", path);
            return (const Loader*)nullptr;
        };
        for (const Loader* loader : jit) {
            Diagnostics diag;
            ((Loader*)loader)->loadDependents(diag, *cacheState, options);
            if (diag.hasError()) { fprintf(stderr,"cached generation refused: %s\n",diag.errorMessageCStr()); return 2; }
        }
        Array<const Loader*> all(jit.data(), jit.size(), jit.size());
        Diagnostics diag;
        const auto* set = PrebuiltLoaderSet::makeDyldCachePrebuiltLoaders(diag, state, all);
        if (diag.hasError() || !set) { fprintf(stderr,"cached serialization refused: %s\n",diag.errorMessageCStr()); return 2; }
        int fd = ::open(outputPath, O_WRONLY|O_CREAT|O_EXCL, 0600);
        if (fd == -1) return 2;
        ssize_t written = ::write(fd, set, set->size());
        ::close(fd);
        if (written != set->size()) return 2;
        printf("generated cached bytes=%llu loaders=%zu version=0x%x\n", (uint64_t)set->size(), set->loaderCount(), ((const uint32_t*)set)[1]);
        return 0;
    }
    state.resetCachedDylibsArrays(cachedSet);
    __block Diagnostics diag;
    RuntimeState* statePtr = &state;
    __block int status = 2;
    mainMF->withFileLayout(diag, ^(const mach_o::Layout& layout) {
        Loader::LoadOptions::Finder finder = ^(Diagnostics& localDiag, mach_o::Platform platform, const char* path, const Loader::LoadOptions& options) {
            uint32_t imageIndex;
            // As dyld's path variants: a Catalyst process takes a dylib's /System/iOSSupport twin first
            if (platform == mach_o::Platform::macCatalyst && path[0] == '/' && strncmp(path, "/System/iOSSupport/", 19) != 0) {
                std::string twin = std::string("/System/iOSSupport") + path;
                if (cache->hasImagePath(twin.c_str(), imageIndex)) return (const Loader*)cachedSet->atIndex(imageIndex);
            }
            if (cache->hasImagePath(path, imageIndex)) return (const Loader*)cachedSet->atIndex(imageIndex);
            if (const auto* loader = cachedSet->findLoader(*statePtr, path)) return (const Loader*)loader;
            return Loader::getLoader(localDiag, *statePtr, path, options);
        };
        if (Loader* mainLoader = JustInTimeLoader::makeLaunchLoader(diag, *statePtr, mainMF, virtualPath, &layout)) {
            __block MissingPaths missingPaths;
            Loader::LoadChain chain{nullptr, mainLoader};
            Loader::LoadOptions options;
            options.staticLinkage = true;
            options.launching = true;
            options.canBeDylib = true;
            options.rpathStack = &chain;
            options.finder = finder;
            options.pathNotFoundHandler = ^(const char* missing) { missingPaths.addPath(missing); };
            mainLoader->loadDependents(diag, *statePtr, options);
            if (diag.hasError()) return;
            for (const Loader* loader : statePtr->loaded) if (auto* prebuilt = loader->isPrebuiltLoader()) prebuilt->setFixedUp(*statePtr);
            std::vector<const Loader*> all;
            for (const Loader* loader : statePtr->loaded) all.push_back(loader);
            std::span<const Loader*> allSpan(all.data(), all.size());
            statePtr->partitionDelayLoads(allSpan, allSpan.subspan(0, 1));
            statePtr->setMainLoader(mainLoader);
            const auto* set = PrebuiltLoaderSet::makeLaunchSet(diag, *statePtr, missingPaths);
            if (diag.hasError() || !set) return;
            int fd = ::open(outputPath, O_WRONLY|O_CREAT|O_EXCL, 0600);
            if (fd == -1) { diag.error("refusing output open"); return; }
            ssize_t count = ::write(fd, set, set->size());
            ::close(fd);
            if (count != set->size()) { diag.error("partial output write"); return; }
            printf("generated bytes=%llu appLoaders=%zu cacheLoaders=%u version=0x%x\n", (uint64_t)set->size(), set->loaderCount(), imageCount, ((const uint32_t*)set)[1]);
            status = 0;
        }
    });
    if (diag.hasError()) fprintf(stderr,"generation refused: %s\n",diag.errorMessageCStr());
    return status;
}
