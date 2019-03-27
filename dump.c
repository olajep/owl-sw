#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>

#if 0
/* When things stabilize and we can move it to the sysroot */
#include <linux/owl.h>
#else
#define __user /* This is stripped from uapi headers by linux */
#include "owl.h"
#endif
#include "owl-user.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define max(x,y) (x > y ? x : y)
#define min(x,y) (x > y ? y : x)

#define ERROR_ON(cond, fmt, ...)				\
do {								\
	if (cond) {						\
		fprintf(stderr, "ERROR: " fmt, __VA_ARGS__);	\
		exit(EXIT_FAILURE);				\
	}							\
} while (0)

#define WARN_ON_ONCE(cond, fmt, ...)				\
do {								\
	static int _warned = 0;					\
	if (!_warned && cond) {					\
		fprintf(stderr, "WARNING: " fmt, __VA_ARGS__);	\
		_warned = 1;					\
	}							\
} while (0)

typedef long long unsigned int llu_t;

/* Bytes */
static size_t
owl_trace_size(union owl_trace trace)
{
	return (trace.kind & 1) ? 8 : 4;
}

/* HACK: We should be able to pull exact trace size from hardware */
static int
owl_trace_empty_p(union owl_trace trace)
{
	const union owl_trace empty = { 0 };

	return memcmp(&trace, &empty, sizeof(empty)) == 0;
}

static uint64_t
timestamp_trace_to_clocks(union owl_trace curr, union owl_trace prev,
			  uint64_t absclocks)
{
	uint64_t currclocks, prevclocks;
	const int width = 61;

	/* Assume we will never overflow 64 bits.
	 * This translates to >100 years at 5GHz */

	currclocks = curr.timestamp.timestamp;
	prevclocks = prev.timestamp.timestamp;

	/* Assume that (prevclocks == currclocks) is not a wrap but rather
	 * triggered by a duplicate timestamp caused by H/W bug. */
	WARN_ON_ONCE(prevclocks == currclocks,
		     "Treating timestamp as duplicate t=[%020llu]\n",
		     (llu_t) curr.timestamp.timestamp);
	if (prevclocks > currclocks) {
		/* Timestamp wrapped */
		absclocks += (1ULL << width);
	}

	absclocks  &= ~((1ULL << width) - 1);
	currclocks &=  ((1ULL << width) - 1);

	return absclocks | currclocks;
}

struct print_args {
	union owl_trace trace;
	union owl_trace from;
	size_t level;
	uint64_t absclocks;
	const struct owl_map_info *maps;
	size_t num_map_entries;
	const struct owl_metadata_entry *current_task;
};

static void
print_uecall_trace(struct print_args *a)
{
	/* TODO: Support hcall if we add support for it in H/W */
	printf("@=[%020llu] ecall\t\tfunction=[%05d]\n",
	       (llu_t) a->absclocks, a->trace.ecall.regval);
}

static void
print_secall_trace(struct print_args *a)
{
	/* TODO: Support hcall if we add support for it in H/W */
	printf("@=[%020llu] mcall\t\tfunction=[%05d]\n",
	       (llu_t) a->absclocks, a->trace.ecall.regval);
}

struct map_search_key {
	int pid;
	uint32_t pc;
};
struct owl_map_info *find_map(const struct map_search_key *key,
			      const struct owl_map_info *maps,
			      size_t num_map_entries);

static void
print_return_trace(struct print_args *a)
{
	/* TODO: Support hcall if we add support for it in H/W */
	/* TODO: Print time delta */
	const char *name;

	const char *binary = "'none'";
	uint64_t offset = a->trace.ret.pc;

	switch (a->from.kind) {
	case OWL_TRACE_KIND_UECALL: name = "eret "; break;
	case OWL_TRACE_KIND_SECALL: name = "mret "; break;
	case OWL_TRACE_KIND_EXCEPTION:
		name = a->from.exception.cause & 128 ? "iret " : "exret"; break;
	default:
		printf("return trace kind=%d\n", a->trace.kind);
		return;
	}

	if (a->level == 0) {
		struct owl_map_info *map;
		struct map_search_key key = {
			.pid = a->current_task->pid,
			.pc = a->trace.ret.pc
		};

		assert(a->from.kind == OWL_TRACE_KIND_UECALL ||
		       a->from.kind == OWL_TRACE_KIND_EXCEPTION);

		map = find_map(&key, a->maps, a->num_map_entries);;

		if (map) {
			/* The Linux kernels file_path() writes the string to
			 * the buffer backwards and pads the beginning with
			 * zeroes */
			binary = &map->path[OWL_PATH_MAX - 2];
			while (*binary != '\0' && binary != map->path) {
				if (binary[-1] == '\0')
					break;
				binary--;
			}
			/* PC is only 32 bits but vm_start is 64 bits */
			offset = a->trace.ret.pc - (uint32_t) map->vm_start;
		}
	} else {
		binary = "'vmlinux'";
		/* offset = a->trace.ret.pc |
		 * 		$(objdump -f vmlinux | grep "start address) */
	}

	printf("@=[%020llu] %s\t\tpc=[%08x] retval=[%05d] file=[%s+0x%llx]\n",
	       (llu_t) a->absclocks, name,
	       a->trace.ret.pc, a->trace.ret.regval, binary, (llu_t) offset);
}

static void
print_exception_trace(struct print_args *a)
{
	/* Exception causes */
	const char *causes[16] = {
		[0x0] = "misaligned_fetch",
		[0x1] = "fetch_access",
		[0x2] = "illegal_instruction",
		[0x3] = "breakpoint",
		[0x4] = "misaligned_load",
		[0x5] = "load_access",
		[0x6] = "misaligned_store",
		[0x7] = "store_access",
		[0x8] = "user_ecall",
		[0x9] = "supervisor_ecall",
		[0xa] = "hypervisor_ecall",
		[0xb] = "machine_ecall",
		[0xc] = "fetch_page_fault",
		[0xd] = "load_page_fault",
		[0xe] = "???",
		[0xf] = "store_page_fault"
	};

	/* Standard interrupts: */
	const char *interrupts[16] = {
		[11] = "MEI",
		[ 3] = "MSI",
		[ 7] = "MTI",
		[ 9] = "SEI",
		[ 1] = "SSI",
		[ 5] = "STI",
		[ 8] = "UEI",
		[ 0] = "USI",
		[ 4] = "UTI"
	};

	const char *type, *name, *desc;
	unsigned cause = a->trace.exception.cause;

	if (cause & 128) {
		cause &= ~128;
		type = "interrupt";
		desc = "irqno";
		name = cause < ARRAY_SIZE(interrupts) ?
			interrupts[cause] : "???";
	} else {
		type = "exception";
		desc = "cause";
		name = cause < ARRAY_SIZE(causes) ?
			causes[cause] : "???";
	}
	name = name ? : "???";

	printf("@=[%020llu] %s\t%s=[0x%03x] name=%s\n",
	       (llu_t) a->absclocks, type, desc, cause, name);
}

static void
print_timestamp_trace(struct print_args *a)
{
	assert(a->absclocks == a->trace.timestamp.timestamp);
	printf("@=[%020llu] timestamp\tt=[%020llu]\n",
	       (llu_t) a->absclocks, (llu_t) a->trace.timestamp.timestamp);
}

static void
print_invalid_trace(struct print_args *a)
{
	long long data;
	unsigned kind = a->trace.kind;
	memcpy(&data, &a->trace, sizeof(data));
	printf("INVALID TRACE kind=%u data=[%016llx]\n", kind, data);
}

static void
(* const print_trace[8]) (struct print_args *a) = {
	[OWL_TRACE_KIND_UECALL]		= print_uecall_trace,
	[OWL_TRACE_KIND_RETURN]		= print_return_trace,
	[OWL_TRACE_KIND_SECALL]		= print_secall_trace,
	[OWL_TRACE_KIND_TIMESTAMP]	= print_timestamp_trace,
	[OWL_TRACE_KIND_EXCEPTION]	= print_exception_trace,
	[5]				= print_invalid_trace,
	[6]				= print_invalid_trace,
	[7]				= print_invalid_trace,
};

void print_metadata(const struct owl_metadata_entry *entry, uint64_t absclocks)
{
	assert(entry->comm[OWL_TASK_COMM_LEN - 1] == '\0');
	printf("@=[%020llu] sched\t\tcomm=[%s] until=[%020llu] cpu=[%d]\n",
	       (llu_t) absclocks,  entry->comm, (llu_t) entry->timestamp, (int) entry->cpu);
}

int find_compare_maps(const void *_key, const void *_elem)
{
	const struct map_search_key *key = _key;
	const struct owl_map_info *elem = _elem;
	uint32_t vm_start, vm_end;

	/* key->pc is only 32 bits (and not shifted TODO IN hardware)
	 * so we hope for a mapping with no duplicates */
	vm_start = (uint32_t) elem->vm_start;
	vm_end = (uint32_t) elem->vm_end;

	if (key->pid < elem->pid)
		return -1;
	if (key->pid > elem->pid)
		return 1;

	if (key->pc < vm_start)
		return -1;
	if (key->pc > vm_end)
		return 1;

	return 0;
}

struct owl_map_info *
find_map(const struct map_search_key *key,
	 const struct owl_map_info *maps, size_t num_map_entries)
{
	return bsearch(key, maps, num_map_entries, sizeof(*maps),
		       find_compare_maps);
}

int
sort_compare_maps(const void *_a, const void *_b)
{
	const struct owl_map_info *a = _a;
	const struct owl_map_info *b = _b;

	if (a->pid < b->pid)
		return -1;
	if (a->pid > b->pid)
		return 1;

	if (a->vm_start < b->vm_start)
		return -1;
	if (a->vm_start > b->vm_start)
		return 1;

	if (a->vm_end < b->vm_end)
		return -1;
	if (a->vm_end > b->vm_end)
		return 1;

	return 0;
}

void
sort_maps(struct owl_map_info *maps, size_t num_map_entries)
{
	qsort(maps, num_map_entries, sizeof(*maps), sort_compare_maps);
}

void dump_trace(const uint8_t *tracebuf, size_t tracebuf_size,
		const struct owl_metadata_entry *metadata, size_t metadata_size,
		struct owl_map_info *maps, size_t map_info_size)
{
	/* TODO: Add support for nested interrupts */

	size_t i = 0;
	const size_t num_meta_entries = metadata_size / sizeof(*metadata);
	const size_t num_map_entries = map_info_size / sizeof(*maps);
	int recursion = 0;
	union owl_trace trace, prev[3] = { 0 }, prev_timestamp = { 0 };
	uint64_t absclocks = 0, msbclocks = 0, next_sched;
	unsigned prev_lsb_timestamp = 0;
	const struct owl_metadata_entry *current_task = &metadata[0];
	const struct owl_metadata_entry
		*metadata_end = &metadata[num_meta_entries];

	/* Sort the map info so we can binary search it */
	sort_maps(maps, num_map_entries);

	/* Recursion levels:
	 * 0: ecall <--> 1: mcall <--> 2: (interrupt or exception) */

	/* The first trace should be a timestamp. */
	memcpy(&trace, &tracebuf[0], min(8, tracebuf_size));
	ERROR_ON(trace.kind != OWL_TRACE_KIND_TIMESTAMP,
		 "%s", "First trace is not a timestamp!\n");
	i += owl_trace_size(trace);

	/* Walk trace buffer to determine initial recursion level. */
	for (; i < tracebuf_size; i += owl_trace_size(trace)) {
		memcpy(&trace, &tracebuf[i], min(8, tracebuf_size - i));

		/* HACK: We should be able to get the exact size from the
		   driver.  */
		if (owl_trace_empty_p(trace))
			break;

		switch (trace.kind) {
		case OWL_TRACE_KIND_SECALL:
		case OWL_TRACE_KIND_EXCEPTION:
			recursion++;
		case OWL_TRACE_KIND_UECALL:
			break;
		case OWL_TRACE_KIND_RETURN:
			recursion++;
		default: continue;
		}
		break;
	}

	/* Initialize with sane values */
	prev[0].kind = OWL_TRACE_KIND_UECALL;
	prev[1].kind = OWL_TRACE_KIND_SECALL;
	prev[2].kind = OWL_TRACE_KIND_SECALL;

	/* Print first scheduled task */
	if (current_task < metadata_end) {
		memcpy(&trace, &tracebuf[0], min(8, tracebuf_size));
		print_metadata(current_task, trace.timestamp.timestamp);
		next_sched = current_task->timestamp;
	}

	for (i = 0; i < tracebuf_size; i += owl_trace_size(trace)) {
		memcpy(&trace, &tracebuf[i], min(8, tracebuf_size - i));

		/* HACK: We should be able to get the exact size from the
		   driver. */
		if (owl_trace_empty_p(trace))
			break;

		if (trace.kind == OWL_TRACE_KIND_TIMESTAMP) {
			msbclocks = timestamp_trace_to_clocks(trace,
							      prev_timestamp,
							      msbclocks);
			/* Only care about the higher bits.
			 * The lower bits will be in the individual traces. */
			msbclocks &= ~((1ULL << 18) - 1);
			prev_timestamp = trace;
		} else if (prev_lsb_timestamp >= trace.lsb_timestamp) {
			/* Timestamp wrapped */
			msbclocks += (1ULL << 18);
		}
		absclocks = msbclocks | trace.lsb_timestamp;

		if (absclocks > next_sched) {
			if (current_task < metadata_end) {
				current_task++;
				print_metadata(current_task, next_sched);
				next_sched = current_task->timestamp;
			}
		}

		if (trace.kind == OWL_TRACE_KIND_RETURN) {
			assert(recursion != 0);
			if (recursion != 0)
				recursion--;
		} else if (trace.kind != OWL_TRACE_KIND_TIMESTAMP) {
			prev[recursion] = trace;
			recursion++;
		}
		assert(recursion < 3);

		{
			struct print_args args = {
				.trace			= trace,
				.from			= prev[recursion],
				.level			= recursion,
				.absclocks		= absclocks,
				.maps			= maps,
				.num_map_entries	= num_map_entries,
				.current_task		= current_task
			};
			print_trace[trace.kind](&args);
		}

		prev_lsb_timestamp = trace.lsb_timestamp;
	}
}

int map_file(char *path, const void **ptr, size_t *size)
{
	const void *mem;
	int fd, err;
	struct stat sb;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return fd;

	err = fstat(fd, &sb);
	if (err < 0)
		return err;

	mem = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED)
		return -1;

	*ptr = mem;
	*size = sb.st_size;

	return fd;
}

int
main(int argc, char *argv[])
{
	const uint8_t *buf, *tracebuf;
	const struct owl_trace_file_header *file_header;
	const struct owl_metadata_entry *metadata;
	struct owl_map_info *map_info;
	int fd;
	size_t buf_size, tracebuf_size, metadata_size, map_info_size;

	/* Disable line buffering */
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	if (argc < 2) {
		fprintf(stderr, "usage: %s [FILE]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	fd = map_file(argv[1], (const void **) &buf, &buf_size);
	if (fd < 0) {
		perror(argv[0]);
		fprintf(stderr, "usage: %s [FILE]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	file_header = (const struct owl_trace_file_header *) buf;
	if (file_header->magic != OWL_TRACE_FILE_HEADER_MAGIC) {
		fprintf(stderr, "invalid trace\n");
		exit(EXIT_FAILURE);
	}

	tracebuf = (const uint8_t *) &file_header[1];
	tracebuf_size = file_header->tracebuf_size;
	metadata =
		(const struct owl_metadata_entry *) (tracebuf + tracebuf_size);
	metadata_size = file_header->metadata_size;
	map_info = (struct owl_map_info *)
		(((uintptr_t) metadata) + metadata_size);
	map_info_size = file_header->map_info_size;
	dump_trace(tracebuf, tracebuf_size,
		   metadata, metadata_size,
		   map_info, map_info_size);

	munmap((void *) buf, buf_size);
	close(fd);

	return 0;
}
