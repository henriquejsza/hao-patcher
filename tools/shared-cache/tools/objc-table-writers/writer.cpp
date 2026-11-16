// Host-only adapter for unchanged pinned dyld ObjC writers and lookup readers.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <sys/mman.h>
#include "OptimizerObjC.h"

static void check(bool condition, const char* message) {
    if (!condition) { fprintf(stderr, "%s\n", message); exit(2); }
}
struct Input {
    std::vector<uint8_t> bytes;
    size_t position = 0;
    template<class T> T take() {
        check(position <= bytes.size() && sizeof(T) <= bytes.size()-position, "truncated fixture");
        T value; memcpy(&value, bytes.data()+position, sizeof(T)); position += sizeof(T); return value;
    }
    const char* string(uint32_t length) {
        check(position < bytes.size() && length < bytes.size()-position, "truncated string");
        const char* result = (const char*)bytes.data()+position;
        check(result[length] == 0 && strlen(result) == length, "invalid string");
        position += length+1; return result;
    }
};
// The writer is templated over its multimap. This explicit ordered multimap
// retains decoded duplicate-array/lookup order rather than guessing the old
// builder's unordered-container iteration order. Every original byte is tested.
struct OrderedObjects {
    using Entry = std::pair<const char*, std::pair<uint64_t,uint16_t>>;
    using const_iterator = std::vector<Entry>::const_iterator;
    std::vector<Entry> entries;
    std::unordered_map<std::string_view,std::pair<size_t,size_t>> ranges;
    const_iterator begin() const { return entries.begin(); }
    const_iterator end() const { return entries.end(); }
    size_t count(const char* name) const { auto r=ranges.at(name); return r.second-r.first; }
    std::pair<const_iterator,const_iterator> equal_range(const char* name) const {
        auto r=ranges.at(name); return {entries.begin()+r.first, entries.begin()+r.second};
    }
    void append(const char* name, uint64_t address, uint16_t index) {
        auto found = ranges.find(name);
        if (found == ranges.end()) ranges.emplace(name,std::pair(entries.size(),entries.size()+1));
        else { check(found->second.second == entries.size(),"noncontiguous object group"); found->second.second++; }
        entries.push_back({name,{address,index}});
    }
};
int main(int argc, char** argv) {
    check(argc==3, "usage: writer fixture output");
    std::ifstream stream(argv[1],std::ios::binary); check(stream.good(),"fixture open failed");
    Input in; in.bytes.assign(std::istreambuf_iterator<char>(stream),{});
    check(in.take<uint32_t>()==0x3157544f,"fixture magic");
    uint32_t kind=in.take<uint32_t>(), count=in.take<uint32_t>(), objectCount=in.take<uint32_t>();
    uint64_t stringsBase=in.take<uint64_t>(), tableAddress=in.take<uint64_t>();
    uint64_t cacheBase=in.take<uint64_t>(), reserve=in.take<uint64_t>();
    check(kind>=1 && kind<=3 && count>0 && count<=(1<<22),"invalid kind/count");
    check(reserve>=1056 && reserve<=(1<<29) && tableAddress<=UINT64_MAX-reserve,"invalid reservation");
    std::vector<objc::ObjCString> strings; strings.reserve(count);
    uint64_t minimum=tableAddress, maximum=tableAddress+reserve;
    for (uint32_t i=0;i<count;i++) {
        uint32_t offset=in.take<uint32_t>(), length=in.take<uint32_t>();
        check(length>0 && length<(1<<20) && stringsBase<=UINT64_MAX-offset-length-1,"invalid string shape");
        uint64_t target=stringsBase+offset;
        int64_t delta=(int64_t)(target-tableAddress); check(delta>=INT32_MIN && delta<=INT32_MAX && delta!=0,"string range");
        check(target+length+1<=tableAddress || target>=tableAddress+reserve,"string overlaps table reservation");
        strings.emplace_back(std::string_view(in.string(length),length),offset);
        minimum=std::min(minimum,target); maximum=std::max(maximum,target+length+1);
    }
    OrderedObjects objects; objects.entries.reserve(objectCount);
    for (uint32_t i=0;i<objectCount;i++) {
        uint32_t name=in.take<uint32_t>(); uint64_t address=in.take<uint64_t>(); uint16_t owner=in.take<uint16_t>();
        check(name<count && address>cacheBase && address-cacheBase<(1ULL<<47),"invalid object");
        objects.append(strings[name].first.data(),address,owner);
    }
    check(in.position==in.bytes.size(),"trailing fixture bytes");
    for (const auto& group:objects.ranges) check(group.second.second-group.second.first<65536,"object multiplicity overflow");
    check((kind==1 && objectCount==0) || (kind!=1 && objects.ranges.size()==count),"object key membership differs");
    check(maximum>minimum && maximum-minimum<=(1ULL<<33),"host virtual window too large");
    size_t windowSize=maximum-minimum;
    uint8_t* window=(uint8_t*)mmap(nullptr,windowSize,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    check(window!=MAP_FAILED,"host-only memory allocation failed");
    for (auto& s:strings) memcpy(window+(stringsBase+s.second-minimum),s.first.data(),s.first.size()+1);
    uint8_t* output=window+(tableAddress-minimum);
    Diagnostics diag; size_t size=0; size_t lookups=0; size_t values=0;
    if (kind==1) {
        auto* table=new(output) objc::SelectorHashTable;
        table->write(diag,stringsBase,tableAddress,reserve,strings);
        check(!diag.hasError(),diag.hasError()?diag.errorMessageCStr():""); size=table->size();
        for (auto& s:strings) {
            const char* found=table->get(s.first.data());
            check(found==(const char*)window+(stringsBase+s.second-minimum),"source selector lookup differs"); lookups++;
        }
    } else {
        auto verify=[&](auto* table) {
            for (auto& s:strings) {
                const auto expected=objects.equal_range(s.first.data());
                __block size_t index=0;
                auto callback=^(uint64_t offset,uint16_t owner,bool& stop) {
                    check(index<(size_t)(expected.second-expected.first),"source object lookup excess");
                    auto e=expected.first[index++].second;
                    check(offset==e.first-cacheBase && owner==e.second,"source object lookup differs");
                };
                if constexpr (std::is_same_v<std::remove_pointer_t<decltype(table)>,objc::ClassHashTable>)
                    table->forEachClass(s.first.data(),callback);
                else table->forEachProtocol(s.first.data(),callback);
                check(index==(size_t)(expected.second-expected.first),"source object lookup missing");
                lookups++; values+=index;
            }
        };
        if (kind==2) {
            auto* table=new(output) objc::ClassHashTable;
            table->write(diag,stringsBase,tableAddress,cacheBase,reserve,strings,objects);
            check(!diag.hasError(),diag.hasError()?diag.errorMessageCStr():""); size=table->size(); verify(table);
        } else {
            auto* table=new(output) objc::ProtocolHashTable;
            table->write(diag,stringsBase,tableAddress,cacheBase,reserve,strings,objects);
            check(!diag.hasError(),diag.hasError()?diag.errorMessageCStr():""); size=table->size(); verify(table);
        }
    }
    check(size<=reserve,"source table exceeds reservation");
    std::ofstream dest(argv[2],std::ios::binary); dest.write((const char*)output,size); check(dest.good(),"output failed");
    printf("{\"bytes\":%zu,\"source_lookup_keys\":%zu,\"source_lookup_values\":%zu}\n",size,lookups,values);
    munmap(window,windowSize);
}
