#ifndef _OWL_USER_H_
#define _OWL_USER_H_

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Little endian */

#define OWL_TRACE_FILE_HEADER_MAGIC    0x00706d75646c776fULL /* "owldump" */
#define OWL_TRACE_FILE_HEADER_SENTINEL 0x00646e65706d7564ULL /* "dumpend" */

struct owl_trace_file_header {
	uint64_t magic;
	uint32_t trace_format;
	uint16_t num_cpus;
	uint64_t:48; /* reserved */
	uint64_t stream_info_size;
	uint64_t stream_info_offs;
	uint64_t tracebuf_size;
	uint64_t tracebuf_offs;
	uint64_t sched_info_size;
	uint64_t sched_info_offs;
	uint64_t map_info_size;
	uint64_t map_info_offs;
	uint64_t sentinel;
} __attribute__((packed));

struct owl_trace_file_cpu_header {
	uint16_t cpu;
	uint64_t:48; /* reserved */
	uint64_t size; /* size of the trace for this cpu */
} __attribute__((packed));

#if defined(__cplusplus)
}
#endif

#endif
