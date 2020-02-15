#include <string>
#include <map>
#include <cstdint>
#include <cstring>

#include "source_hashmap.h"

namespace hashmap {
	std::string make_key(const char *binary_, uint64_t vaddr_)
	{
		return (std::string(binary_) + "+" + std::to_string(vaddr_));
	}

	typedef std::map<std::string, std::string> hashmap;
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
source_hash_find(void *p, const char *binary, uint64_t vaddr, char *buf, size_t buflen)
{
    hashmap::hashmap *map = (hashmap::hashmap *) p;
    std::string key(hashmap::make_key(binary, vaddr));
    if (map->find(key) != map->end()) {
        std::string v = (*map)[key];
        strncpy(buf, v.c_str(), buflen);
        return true;
    } else
        return false;
}

void
source_hash_insert(void *p, const char *binary, uint64_t vaddr, const char *value)
{
    hashmap::hashmap *map = (hashmap::hashmap *) p;
    std::string key(hashmap::make_key(binary, vaddr));
    (*map)[key] = std::string(value);
}
};
