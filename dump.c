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

static void
print_uecall_trace(union owl_trace trace, union owl_trace from, size_t level,
		   uint64_t absclocks)
{
	(void) from;
	(void) level;

	/* TODO: Support hcall if we add support for it in H/W */
	printf("@=[%020llu] ecall\t\tfunction=[%05d]\n",
	       (llu_t) absclocks | trace.ecall.timestamp, trace.ecall.regval);
}

static void
print_secall_trace(union owl_trace trace, union owl_trace from, size_t level,
		   uint64_t absclocks)
{
	(void) from;
	(void) level;

	/* TODO: Support hcall if we add support for it in H/W */
	printf("@=[%020llu] mcall\t\tfunction=[%05d]\n",
	       (llu_t) absclocks | trace.ecall.timestamp, trace.ecall.regval);
}

static void
print_return_trace(union owl_trace trace, union owl_trace from, size_t level,
		   uint64_t absclocks)
{
	(void) level;

	/* TODO: Support hcall if we add support for it in H/W */
	/* TODO: Print time delta */
	char *name;
	switch (from.kind) {
	case OWL_TRACE_KIND_UECALL: name = "eret "; break;
	case OWL_TRACE_KIND_SECALL: name = "mret "; break;
	case OWL_TRACE_KIND_EXCEPTION:
		name = from.exception.cause & 128 ? "iret " : "exret" ; break;
	default:
		printf("return trace kind=%d\n", trace.kind);
		return;
	}
	printf("@=[%020llu] %s\t\tpc=[%08x] retval=[%05d]\n",
	       (llu_t) absclocks | trace.ret.timestamp, name, trace.ret.pc,
	       trace.ret.regval);
}

static void
print_exception_trace(union owl_trace trace, union owl_trace from, size_t level,
		      uint64_t absclocks)
{
	(void)level;
	(void)from;

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
	unsigned cause = trace.exception.cause;

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
	       (llu_t) absclocks | trace.exception.timestamp, type, desc,
	       cause, name);
}

static void
print_timestamp_trace(union owl_trace trace, union owl_trace from, size_t level,
		      uint64_t absclocks)
{
	(void)level;
	(void)from;

	printf("@=[%020llu] timestamp\tt=[%020llu]\n",
	       (llu_t) absclocks | trace.timestamp.timestamp,
	       (llu_t) trace.timestamp.timestamp);
}

static void
print_invalid_trace(union owl_trace trace, union owl_trace from, size_t level,
		    uint64_t absclocks)
{
	(void)from;
	(void)level;
	(void)absclocks;
	long long data;
	unsigned kind = trace.kind;
	memcpy(&data, &trace, sizeof(data));
	printf("INVALID TRACE kind=%u data=[%016llx]\n", kind, data);
}

static void
(* const print_trace[8]) (union owl_trace, union owl_trace, size_t,
			  uint64_t) = {
	[OWL_TRACE_KIND_UECALL]		= print_uecall_trace,
	[OWL_TRACE_KIND_RETURN]		= print_return_trace,
	[OWL_TRACE_KIND_SECALL]		= print_secall_trace,
	[OWL_TRACE_KIND_TIMESTAMP]	= print_timestamp_trace,
	[OWL_TRACE_KIND_EXCEPTION]	= print_exception_trace,
	[5]				= print_invalid_trace,
	[6]				= print_invalid_trace,
	[7]				= print_invalid_trace,
};

void dump_metadata(const struct owl_metadata_entry *metadata,
		   size_t metadata_size)
{
	size_t i, nentries = metadata_size / sizeof(*metadata);
	const struct owl_metadata_entry *entry;
	for (i = 0; i < nentries; i++) {
		entry = &metadata[i];
		assert(entry->comm[OWL_TASK_COMM_LEN - 1] == '\0');
		printf("@=[%llu] %s %d\n",
		       (llu_t) entry->timestamp, entry->comm, (int) entry->cpu);
	}
}

void dump_trace(const uint8_t *buf, size_t buf_size)
{
	/* TODO: Add support for nested interrupts */

	size_t i = 0;
	int recursion = 0;
	union owl_trace trace, prev[3] = { 0 }, prev_timestamp = { 0 };
	uint64_t absclocks = 0;
	unsigned prev_lsb_timestamp = 0;

	/* Recursion levels:
	 * 0: ecall <--> 1: mcall <--> 2: (interrupt or exception) */

	/* The first trace should be a timestamp. */
	memcpy(&trace, &buf[0], min(8, buf_size));
	ERROR_ON(trace.kind != OWL_TRACE_KIND_TIMESTAMP,
		 "%s", "First trace is not a timestamp!\n");
	i += owl_trace_size(trace);

	/* Walk trace buffer to determine initial recursion level. */
	for (; i < buf_size; i += owl_trace_size(trace)) {
		memcpy(&trace, &buf[i], min(8, buf_size - i));

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

	for (i = 0; i < buf_size; i += owl_trace_size(trace)) {
		memcpy(&trace, &buf[i], min(8, buf_size - i));

		/* HACK: We should be able to get the exact size from the
		   driver. */
		if (owl_trace_empty_p(trace))
			break;

		if (prev_lsb_timestamp >= trace.lsb_timestamp) {
			/* Timestamp wrapped */
			absclocks += (1ULL << 18);
		}

		if (trace.kind == OWL_TRACE_KIND_TIMESTAMP) {
			absclocks = timestamp_trace_to_clocks(trace,
							      prev_timestamp,
							      absclocks);
			/* Only care about the higher bits.
			 * The lower bits will be in the individual traces. */
			absclocks &= ~((1ULL << 18) - 1);
			prev_timestamp = trace;
		} else if (trace.kind == OWL_TRACE_KIND_RETURN) {
			assert(recursion != 0);
			if (recursion != 0)
				recursion--;
		} else {
			prev[recursion] = trace;
			recursion++;
		}
		assert(recursion < 3);

		print_trace[trace.kind](trace, prev[recursion], recursion,
					absclocks);

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
	const uint8_t *buf;
	const struct owl_trace_file_header *file_header;
	const struct owl_metadata_entry *metadata;
	int fd;
	size_t buf_size, trace_size, metadata_size;

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

	trace_size = file_header->tracebuf_size;
	dump_trace(buf + sizeof(struct owl_trace_file_header), trace_size);

	metadata_size = file_header->metadata_size;
	metadata = (const struct owl_metadata_entry *)
		(buf + sizeof(struct owl_trace_file_header) + trace_size);
	dump_metadata(metadata, metadata_size);

	munmap((void *) buf, buf_size);
	close(fd);

	return 0;
}
