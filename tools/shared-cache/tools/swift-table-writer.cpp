// Host adapter for Apple's pointer-key perfect-hash writer and lookup reader.
#include <cstdio>
#include <cstring>
#include <charconv>
#include <fstream>
#include <vector>
#include "OptimizerObjC.h"
#include "OptimizerSwift.h"
#include "Allocator.h"

static void check(bool ok, const char* message) {
    if (!ok) { fprintf(stderr, "%s\n", message); exit(2); }
}
int main(int argc, char** argv) {
    if (argc == 5 && strcmp(argv[1], "--reserve") == 0) {
        uint64_t counts[3]{};
        for (unsigned i = 0; i != 3; ++i) {
            const char* end = argv[i + 2] + strlen(argv[i + 2]);
            auto parsed = std::from_chars(argv[i + 2], end, counts[i]);
            check(parsed.ec == std::errc() && parsed.ptr == end, "invalid table reservation count");
        }
        auto [keys, words, values] = counts;
        check(keys && keys <= (1U << 22) && words >= keys &&
              words <= keys * PointerHashTableKeyMaxPointers && values >= keys,
              "pointer-table reservation extent");
        // PerfectHashWriter.cpp::make_perfect tries the next power of two,
        // then twice that capacity. findhash never grows tab[] beyond capacity.
        // Reserve that upper bound before owned pointers receive addresses.
        struct { uint32_t capacity = 1, mask; } maximum;
        while (maximum.capacity < keys) maximum.capacity *= 2;
        maximum.capacity *= 2;
        maximum.mask = maximum.capacity - 1;
        size_t keyStart = (SwiftHashTable::size(maximum) +
                          values * sizeof(PointerHashTableValue) + 7) & ~size_t(7);
        size_t reservation = keyStart + words * sizeof(uint64_t);
        printf("{\"bytes\":%zu}\n", reservation);
        return 0;
    }
    check(argc == 3, "usage: swift-table-writer input output");
    std::ifstream in(argv[1], std::ios::binary);
    auto number = [&]<class T>() {
        T value{}; in.read((char*)&value, sizeof(value));
        check(in.good(), "truncated pointer-table input"); return value;
    };
    check(number.operator()<uint32_t>() == 0x31545753, "pointer-table input magic");
    uint32_t count = number.operator()<uint32_t>();
    check(count && count <= (1U << 22), "pointer-table key count");
    auto& allocator = lsl::MemoryManager::defaultAllocator();
    lsl::Vector<PointerHashTableBuilderKey> keys(allocator);
    lsl::Vector<PointerHashTableValue> values(allocator);
    std::vector<std::vector<uint64_t>> offsets(count);
    std::vector<objc::PerfectHash::SwiftStrings> hashKeys;
    keys.reserve(count); hashKeys.reserve(count);
    uint32_t keyBytes = 0;
    for (uint32_t i = 0; i != count; ++i) {
        uint32_t n = number.operator()<uint32_t>(), v = number.operator()<uint32_t>();
        check(n && n <= PointerHashTableKeyMaxPointers && v && v < (1U << 20), "pointer-table key/value extent");
        for (uint32_t j = 0; j != n; ++j) offsets[i].push_back(number.operator()<uint64_t>());
        keys.push_back({offsets[i].data(), n});
        for (uint32_t j = 0; j != v; ++j) {
            auto& value = values.emplace_back();
            uint64_t offset = number.operator()<uint64_t>();
            check(offset < (1ULL << 63), "pointer-table value overflow");
            value.offsetToCacheOffsets = keyBytes; value.numOffsets = n;
            value.cacheOffset = offset; value.nextIsDuplicate = j + 1 != v;
        }
        keyBytes += n * sizeof(uint64_t);
    }
    check(in.peek() == EOF, "trailing pointer-table input");
    for (const auto& key : keys)
        hashKeys.push_back({{(uint8_t*)key.key1Buffer(), key.key1Size()},
                            {(uint8_t*)key.key2Buffer(), key.key2Size()}});
    objc::PerfectHash perfect;
    objc::PerfectHash::make_perfect(hashKeys, perfect);
    size_t headerSize = SwiftHashTable::size(perfect), valuesSize = values.size() * sizeof(PointerHashTableValue);
    // Four-entry capacities produce an unaligned end. The key array itself is uint64_t aligned.
    size_t keysStart = (headerSize + valuesSize + 7) & ~size_t(7);
    std::vector<uint8_t> output(keysStart + keyBytes);
    for (auto& value : values) value.offsetToCacheOffsets += keysStart;
    auto* table = (SwiftHashTable*)output.data();
    table->write(perfect, keys, values, output.data() + headerSize);
    memcpy(output.data() + headerSize, values.data(), valuesSize);
    size_t cursor = keysStart;
    for (const auto& key : offsets) {
        memcpy(output.data() + cursor, key.data(), key.size() * 8); cursor += key.size() * 8;
    }
    size_t index = 0;
    for (const auto& key : keys) {
        auto* value = table->getValue<PointerHashTableBuilderKey, PointerHashTableValue>(key, nullptr);
        check(value, "Apple pointer-table lookup missed an emitted key");
        do {
            check(value->cacheOffset == values[index].cacheOffset &&
                  value->nextIsDuplicate == values[index].nextIsDuplicate, "Apple pointer-table lookup value differs");
            ++value; ++index;
        } while (values[index - 1].nextIsDuplicate);
    }
    std::ofstream out(argv[2], std::ios::binary);
    out.write((const char*)output.data(), output.size()); check(out.good(), "pointer-table output failed");
    printf("{\"keys\":%u,\"values\":%zu,\"bytes\":%zu}\n", count, (size_t)values.size(), output.size());
}
