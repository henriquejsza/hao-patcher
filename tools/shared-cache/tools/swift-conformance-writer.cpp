// Host-only adapter to the toolchain's Apple Swift conformance writer and reader.
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <string>
#include <set>
#include <tuple>
#include <sys/mman.h>
#include "OptimizerObjC.h"
#include "OptimizerSwift.h"
#include "Allocator.h"

static void check(bool ok, const char* message) {
    if (!ok) { fprintf(stderr, "%s\n", message); exit(2); }
}
template<class T> static T number(std::ifstream& in) {
    T value{}; in.read((char*)&value, sizeof(value));
    check(in.good(), "truncated conformance input"); return value;
}

template<class Value, class Key, bool Foreign = false>
static void emit(std::ifstream& in, uint32_t count, const char* destination) {
    auto& allocator = lsl::MemoryManager::defaultAllocator();
    lsl::Vector<Value> values(allocator);
    lsl::Vector<Key> keys(allocator);
    std::vector<std::string> names(count);
    std::vector<objc::PerfectHash::SwiftStrings> hashes;
    std::set<std::pair<std::string, uint64_t>> unique;
    values.reserve(count); keys.reserve(count); hashes.reserve(count);
    uint64_t extent = 1;
    std::tuple<uint64_t, uint64_t, uint64_t, uint64_t> previous{};
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t a = number<uint64_t>(in), b = number<uint64_t>(in), raw = number<uint64_t>(in);
        uint64_t offset = Foreign ? a & ((1ULL << 48) - 1) : a;
        uint64_t length = Foreign ? a >> 48 : 0;
        auto order = std::make_tuple(offset, length, b, raw & ~1ULL);
        check(i == 0 || previous <= order, "unsorted conformance input"); previous = order;
        check(b < (1ULL << 47) && !(raw & 1), "invalid protocol offset/duplicate bit");
        auto& value = values.emplace_back();
        static_assert(sizeof(Value) == 24);
        uint64_t words[] = {a, b, raw}; memcpy(&value, words, sizeof(value));
        if constexpr (Foreign) {
            check(offset + std::max(length, uint64_t(1)) <= (1ULL << 36), "foreign name extent");
            names[i].resize(length); in.read(names[i].data(), length);
            check(in.good(), "truncated foreign name");
            extent = std::max(extent, offset + std::max(length, uint64_t(1)));
        } else {
            check(a < (1ULL << 47), "type/metadata offset overflow");
        }
        bool duplicate = i && memcmp(&values[i-1], &value, 16) == 0;
        if (duplicate) {
            if constexpr (Foreign) check(names[i] == names[i-1], "foreign key bytes differ");
            values[i-1].nextIsDuplicate = 1;
            continue;
        }
        if constexpr (Foreign) {
            check(unique.emplace(names[i], b).second, "foreign identity has multiple offsets");
            keys.push_back({std::string_view(names[i]), b});
        } else {
            keys.push_back(static_cast<const Key&>(value));
        }
    }
    check(in.peek() == EOF, "trailing conformance input");
    for (const auto& key : keys) {
        if constexpr (Foreign)
            hashes.push_back({{(uint8_t*)key.foreignDescriptorName.data(), key.foreignDescriptorName.size()},
                              {(uint8_t*)&key.protocolCacheOffset, 8}});
        else
            hashes.push_back({{(uint8_t*)key.key1Buffer(nullptr), key.key1Size()},
                              {(uint8_t*)key.key2Buffer(nullptr), key.key2Size()}});
    }
    objc::PerfectHash perfect{};
    if (hashes.empty()) {
        perfect.capacity = 1; perfect.occupied = 0; perfect.shift = 64;
        perfect.mask = 0; perfect.salt = 0; perfect.tab.resize(1);
    } else {
        objc::PerfectHash::make_perfect(hashes, perfect);
    }
    check(perfect.capacity && perfect.capacity <= (1U << 22), "perfect hash construction failed");
    size_t prefix = SwiftHashTable::size(perfect);
    std::vector<uint8_t> output(prefix + values.size() * sizeof(Value));
    auto* table = (SwiftHashTable*)output.data();
    table->write(perfect, keys, values, output.data() + prefix);
    memcpy(output.data() + prefix, values.data(), values.size() * sizeof(Value));
    uint8_t* strings = nullptr;
    if constexpr (Foreign) {
        strings = (uint8_t*)mmap(nullptr, extent, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        check(strings != MAP_FAILED, "foreign oracle mapping failed");
        for (uint32_t i = 0; i < count; ++i)
            memcpy(strings + values[i].foreignDescriptorNameCacheOffset, names[i].data(), names[i].size());
    }
    size_t index = 0;
    for (const auto& key : keys) {
        const auto* value = table->getValue<Key, Value>(key, strings);
        check(value, "Apple conformance lookup missed emitted key");
        do {
            check(index < values.size() && memcmp(value, &values[index], sizeof(Value)) == 0,
                  "Apple conformance lookup returned different value");
            ++value; ++index;
        } while (values[index-1].nextIsDuplicate);
        auto missing = key; missing.protocolCacheOffset = UINT64_MAX;
        check(!table->getValue<Key, Value>(missing, strings), "Apple conformance lookup false positive");
    }
    check(index == values.size(), "unverified conformance values");
    if constexpr (Foreign) munmap(strings, extent);
    std::ofstream out(destination, std::ios::binary);
    out.write((const char*)output.data(), output.size()); check(out.good(), "conformance output failed");
    printf("{\"keys\":%zu,\"values\":%zu,\"bytes\":%zu,\"misses_checked\":%zu}\n",
           (size_t)keys.size(), (size_t)values.size(), output.size(), (size_t)keys.size());
}
int main(int argc, char** argv) {
    check(argc == 3, "usage: swift-conformance-writer input output");
    std::ifstream in(argv[1], std::ios::binary);
    check(number<uint32_t>(in) == 0x31435753, "conformance input magic");
    uint32_t kind = number<uint32_t>(in), count = number<uint32_t>(in);
    check(count <= 1000000, "conformance input count exceeds bound");
    switch (kind) {
        case 0: emit<SwiftTypeProtocolConformanceLocation, SwiftTypeProtocolConformanceLocationKey>(in, count, argv[2]); break;
        case 1: emit<SwiftMetadataProtocolConformanceLocation, SwiftMetadataProtocolConformanceLocationKey>(in, count, argv[2]); break;
        case 2: emit<SwiftForeignTypeProtocolConformanceLocation, SwiftForeignTypeProtocolConformanceLookupKey, true>(in, count, argv[2]); break;
        default: check(false, "unknown conformance kind");
    }
}
