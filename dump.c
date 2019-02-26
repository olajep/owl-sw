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

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define max(x,y) (x > y ? x : y)
#define min(x,y) (x > y ? y : x)

#define TRACE_KIND_UECALL	0x0 // Usermode ecall
#define TRACE_KIND_SECALL	0x2 // Supervisor ecall
#define TRACE_KIND_EXCEPTION	0x4 // Non-ecall exception / interrupt
#define TRACE_KIND_TIMESTAMP	0x6 // Full 61-bit timestamp
#define TRACE_KIND_RETURN	0x1 // Return from either Ecall or Interrupt

struct ecall_trace {
	unsigned kind:3;
	unsigned timestamp:18;
	unsigned regval:11;
} __attribute__((packed));

struct return_trace {
	unsigned kind:3;
	unsigned timestamp:18;
	unsigned regval:11;
	unsigned pc:32;
} __attribute__((packed));

struct exception_trace {
	unsigned kind:3;
	unsigned timestamp:21;
	unsigned cause:8;
} __attribute__((packed));

struct timestamp_trace {
	unsigned kind:3;
	unsigned timestamp:29;
} __attribute__((packed));

union out_trace {
	unsigned kind:3;
	struct ecall_trace ecall;
	struct return_trace ret;
	struct exception_trace exception;
	struct timestamp_trace timestamp;
} __attribute__((packed));

/* Bytes */
static size_t
out_trace_size(union out_trace trace)
{
	return (trace.kind & 1) ? 8 : 4;
}

static void
print_uecall_trace(union out_trace trace, union out_trace from, size_t level)
{
	(void) from;
	(void) level;

	/* TODO: Support hcall if we add support for it in H/W */
	printf("@=[%020u] ecall\t\tfunction=[%05d]\n",
	       trace.ecall.timestamp, trace.ecall.regval);
}

static void
print_secall_trace(union out_trace trace, union out_trace from, size_t level)
{
	(void) from;
	(void) level;

	/* TODO: Support hcall if we add support for it in H/W */
	printf("@=[%020u] mcall\t\tfunction=[%05d]\n",
	       trace.ecall.timestamp, trace.ecall.regval);
}


static void
print_return_trace(union out_trace trace, union out_trace from, size_t level)
{
	(void) level;

	/* TODO: Support hcall if we add support for it in H/W */
	/* TODO: Print time delta */
	char *name;
	switch (from.kind) {
	case TRACE_KIND_UECALL: name = "eret "; break;
	case TRACE_KIND_SECALL: name = "mret "; break;
	case TRACE_KIND_EXCEPTION:
		name = from.exception.cause & 128 ? "iret " : "exret" ; break;
	default:
		printf("return trace kind=%d\n", trace.kind);
		return;
	}
	printf("@=[%020u] %s\t\tpc=[%08x] retval=[%05d]\n",
	       trace.ret.timestamp, name, trace.ret.pc,
	       trace.ret.regval);
}

static void
print_exception_trace(union out_trace trace, union out_trace from, size_t level)
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

	printf("@=[%020u] %s\t%s=[0x%03x] name=%s\n",
	       trace.exception.timestamp, type, desc, cause, name);
}

static void
print_timestamp_trace(union out_trace trace, union out_trace from, size_t level)
{
	(void)level;
	(void)from;

	printf("@=[%020u] timestamp\n", trace.timestamp.timestamp);
}

static void
print_invalid_trace(union out_trace trace, union out_trace from, size_t level)
{
	(void)from;
	(void)level;
	long long data;
	unsigned kind = trace.kind;
	memcpy(&data, &trace, sizeof(data));
	printf("INVALID TRACE kind=%u data=[%016llx]\n", kind, data);
}

static void
(* const print_trace[8]) (union out_trace, union out_trace, size_t) = {
	[TRACE_KIND_UECALL]	= print_uecall_trace,
	[TRACE_KIND_RETURN]	= print_return_trace,
	[TRACE_KIND_SECALL]	= print_secall_trace,
	[3]			= print_invalid_trace,
	[TRACE_KIND_EXCEPTION]	= print_exception_trace,
	[5]			= print_invalid_trace,
	[TRACE_KIND_TIMESTAMP]	= print_timestamp_trace,
	[7]			= print_invalid_trace,
};

void dump_trace(const uint8_t *buf, size_t buf_size)
{
	/* TODO: Add support for nested interrupts */

	size_t i = 0, recursion = 0;
	union out_trace trace, prev[3] = { 0 };

	/* The first trace could be an mcall from the kernel */
	memcpy(&trace, &buf[i], min(8, buf_size - i));
	if (trace.kind == TRACE_KIND_SECALL)
		recursion = 1;

	/* Initialize with sane values */
	prev[0].kind = TRACE_KIND_UECALL;
	prev[1].kind = TRACE_KIND_SECALL;
	prev[2].kind = TRACE_KIND_SECALL;

	while (i < buf_size) {
		memcpy(&trace, &buf[i], min(8, buf_size - i));

		if (trace.kind == TRACE_KIND_RETURN) {
			assert(recursion != 0);
			if (recursion != 0)
				recursion--;
		} else if (trace.kind != TRACE_KIND_TIMESTAMP) {
			prev[recursion] = trace;
			recursion++;
		}
		assert(recursion < 3);

		print_trace[trace.kind](trace, prev[recursion], recursion);

		i += out_trace_size(trace);
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
	int fd;
	size_t buf_size;

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

	dump_trace(buf, buf_size);
	munmap((void *) buf, buf_size);
	close(fd);

	return 0;
}
