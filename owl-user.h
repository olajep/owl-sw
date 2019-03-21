#ifndef _OWL_USER_H_
#define _OWL_USER_H_

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Little endian */

#define OWL_TRACE_FILE_HEADER_MAGIC 0x00706d75646c776fULL

struct owl_trace_file_header {
	uint64_t magic;
	uint32_t trace_format;
	uint32_t metadata_format;
	uint64_t tracebuf_size;
	uint64_t metadata_size;
	uint64_t map_info_size;
} __attribute__((packed));

#if defined(__cplusplus)
}
#endif

#endif
