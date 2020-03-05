#include <string>
#include <map>
#include <cstdint>
#include <cstring>

#include "source_hashmap.h"

namespace hashmap {
	std::string make_key(const char *binary_, uint64_t paddr_)
	{
		return (std::string(binary_) + "+" + std::to_string(paddr_));
	}

	typedef std::map<std::string, std::tuple<std::string, uint64_t>> hashmap;
}

extern "C" {

void *
source_hash_init()
{
    hashmap::hashmap *map;
    map = new(hashmap::hashmap);
    return (void *) map;
}

void
source_hash_fini(void *p)
{
    hashmap::hashmap *map = (hashmap::hashmap *) p;
    delete(map);
}

bool
source_hash_find(void *p, const char *binary, uint64_t paddr, char *buf, size_t buflen, uint64_t *vaddr)
{
    hashmap::hashmap *map = (hashmap::hashmap *) p;
    std::string key(hashmap::make_key(binary, paddr));
    if (map->find(key) != map->end()) {
        std::tuple<std::string, uint64_t> v = (*map)[key];
        std::string src = std::get<0>(v);
        strncpy(buf, src.c_str(), buflen);
        *vaddr = std::get<1>(v);
        return true;
    } else
        return false;
}

void
source_hash_insert(void *p, const char *binary, uint64_t paddr, const char *value, uint64_t vaddr)
{
    hashmap::hashmap *map = (hashmap::hashmap *) p;
    std::string key(hashmap::make_key(binary, paddr));
    (*map)[key] = make_tuple(std::string(value), vaddr);
}
};
