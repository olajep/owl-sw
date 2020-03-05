#ifndef __hashmap_h__
#define __hashmap_h__
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stddef.h>
extern void *source_hash_init();
extern void source_hash_fini(void *p);
extern bool source_hash_find(void *p, const char *binary, uint64_t paddr, char *buf, size_t buflen, uint64_t *vaddr);
extern void source_hash_insert(void *p, const char *binary, uint64_t paddr, const char *value, uint64_t vaddr);
#ifdef __cplusplus
};
#endif
#endif /* __hashmap_h__ */
