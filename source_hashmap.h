#ifndef __hashmap_h__
#define __hashmap_h__
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stddef.h>
extern void *source_hash_init();
extern void source_hash_fini(void *p);
extern bool source_hash_find(void *p, const char *binary, uint64_t vaddr, char *buf, size_t buflen);
extern void source_hash_insert(void *p, const char *binary, uint64_t vaddr, const char *value);
#ifdef __cplusplus
};
#endif
#endif /* __hashmap_h__ */
