#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdbool.h>
#include <getopt.h>
#include <time.h>

#if 0
/* When things stabilize and we can move it to the sysroot */
#include <linux/owl.h>
#else
#define __user /* This is stripped from uapi headers by linux */
#include "owl.h"
#endif
#include "owl-user.h"
#include "syscalltable.h"
#include "mcalltable.h"
#include "source_hashmap.h"

#define DEFAULT_SYSROOT	"/opt/riscv/sysroot"

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
		fprintf(stdwarn, "WARNING: " fmt, __VA_ARGS__);	\
		_warned = 1;					\
	}							\
} while (0)

#define STRNCMP_LIT(s, lit) strncmp((s), ""lit"", sizeof((lit)-1))

/* Where warnings should be printed to. This is set in main after the call to
 * parse_options_or_die()  */
static FILE *stdwarn = NULL;

/* A preprocessed trace with context */
struct dump_trace {
	uint64_t			timestamp;
	union owl_trace			trace;
	uint64_t			sched_in_timestamp;
	const struct owl_sched_info_full *sched_info;
};

struct formatted_dump_trace {
	uint64_t	timestamp;
	char		buf[256];
};

struct call_frame {
	const struct dump_trace *enter_trace;  /* Trace entering this frame */
	const struct dump_trace *return_trace; /* Trace returning to this frame */
	uint32_t pchi; /* TODO?!?: Move pchi to struct dump_trace??? */
};

struct callstack {
	struct call_frame		frames[3];
	int frameno; /* The 'frame' we're at */
	const struct owl_task		*task;
};

struct print_args {
	/* Used for timestamp pchi & invalid */
	struct dump_trace *trace;

	/* Current task and memory mapping info */
	const struct owl_map_info *maps;
	size_t num_map_entries;

	/* Arch settings */
	unsigned pc_bits;
	bool sign_extend_pc;

	char delim;

	const char *sysroot;

	uint64_t start_time;

	int cpu;

	float clock_freq;
};

struct map_search_key {
	int pid;
	uint64_t pc;
};

typedef long long unsigned int llu_t;
typedef void (* const printfn_t)(union owl_trace);

struct printer {
	printfn_t		*print_trace;
};

/**
 * owl_trace_valid_p - Sanity check trace
 * @trace:	The trace
 *
 * Return: true if trace is valid, false otherwise.
 */
static bool
owl_trace_valid_p(union owl_trace trace)
{
	const union owl_trace empty = { 0 };
	switch (trace.kind) {
	case OWL_TRACE_KIND_UECALL:
	case OWL_TRACE_KIND_RETURN:
	case OWL_TRACE_KIND_SECALL:
	case OWL_TRACE_KIND_TIMESTAMP:
	case OWL_TRACE_KIND_EXCEPTION:
	case OWL_TRACE_KIND_PCHI:
		break;
	default:
		return false;
	}

	return memcmp(&trace, &empty, sizeof(empty)) != 0;
}

/* Begin print helper functions */

static void
describe_exception_trace(union owl_trace trace, const char **type,
			 const char **name, const char **desc, unsigned *cause)
{
	const char *type2;
	const char *name2;
	const char *desc2;
	unsigned cause2;

	type = type == NULL ? &type2 : type;
	name = name == NULL ? &name2 : name;
	desc = desc == NULL ? &desc2 : desc;
	cause = cause == NULL ? &cause2 : cause;

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

	*cause = trace.exception.cause;
	*name = NULL;

	if (*cause & 128) {
		*cause &= ~128;
		*type = "interrupt";
		*desc = "irqno";
		*name = *cause < ARRAY_SIZE(interrupts) ?
			interrupts[*cause] : "???";
	} else {
		*type = "exception";
		*desc = "cause";
		*name = *cause < ARRAY_SIZE(causes) ?
			causes[*cause] : "???";
	}
	*name = *name ? : "???";
}



static void
describe_enter_trace(union owl_trace trace, const char **type,
		     const char **name, const char **desc, unsigned *cause)
{
	const char *type2;
	const char *name2;
	const char *desc2;
	unsigned cause2;

	type = type == NULL ? &type2 : type;
	name = name == NULL ? &name2 : name;
	desc = desc == NULL ? &desc2 : desc;
	cause = cause == NULL ? &cause2 : cause;

	switch (trace.kind) {
	case OWL_TRACE_KIND_UECALL:
		*type = "ecall";
		*desc = "ecall";
		*cause = trace.ecall.regval;
		if (*cause >= ARRAY_SIZE(syscalltable)) {
			fprintf(stdwarn, "WARNING: invalid syscall %d\n", *cause);
			*name = "sys_INVALID";
		} else {
			*name = syscalltable[*cause];
		}
		break;
	case OWL_TRACE_KIND_SECALL:
		*type = "mcall";
		*desc = "mcall";
		*cause = trace.ecall.regval;
		if (*cause >= ARRAY_SIZE(mcalltable)) {
			*name = NULL;
		} else {
			*name = mcalltable[*cause];
		}
		*cause = trace.ecall.regval;
		break;
	case OWL_TRACE_KIND_EXCEPTION:
		describe_exception_trace(trace, type, name, desc, cause);
		break;
	default:
		assert(0 && "Wrong trace kind\n");
	}
}

static void
print_nop(union owl_trace trace)
{
	(void)trace;
}

/* End print helper functions */


/* Begin default output format */

/**
 * print_ecall_trace - Print an ecall trace
 * @a:		Printer arguments
 * @c:		Callstack
 *
 * Return: None
 */
static void
print_ecall_trace(union owl_trace trace)
{
	const char *type, *name;
	unsigned function;

	describe_enter_trace(trace, &type, &name, NULL, &function);
	/* TODO: Support hcall if we add support for it in H/W */
	printf("@=[%020u] %s\t\tfunction=[%05d] name=[%s]\n",
	       trace.lsb_timestamp, type, function, name);
}

/**
 * print_return_trace - Print a return trace
 * @a:		Printer arguments
 * @c:		Callstack
 *
 * Return: None
 */
static void
print_return_trace(union owl_trace trace)
{
	printf("@=[%020u] pc=[%016x] retval=[%05d]\n",
	       trace.lsb_timestamp, trace.ret.pc, trace.ret.regval);
}

/**
 * print_exception_trace - Print an exception trace
 * @a:		Printer arguments
 * @c:		Callstack
 *
 * Return: None
 */
static void
print_exception_trace(union owl_trace trace)
{
	const char *type, *name, *desc;
	unsigned cause;

	describe_enter_trace(trace, &type, &name, &desc, &cause);
	printf("@=[%020u] %s\t%s=[0x%03x] name=%s\n",
	       trace.lsb_timestamp, type, desc, cause, name);
}

/**
 * print_timestamp_trace - Print a timestamp trace
 * @a:		Printer arguments
 * @c:		Callstack
 *
 * Return: None
 */
static void
print_timestamp_trace(union owl_trace trace)
{
	printf("@=[%020llu] timestamp\tt=[%020llu]\n",
	       (llu_t) trace.timestamp.timestamp,
	       (llu_t) trace.timestamp.timestamp);
}

/**
 * print_invalid_trace - Print an invalid trace kind
 * @a:		Printer arguments
 * @c:		Callstack
 *
 * Return: None
 */
static void
print_invalid_trace(union owl_trace trace)
{
	long long data;
	unsigned kind = trace.kind;
	memcpy(&data, &trace, sizeof(data));
	printf("INVALID TRACE kind=%u data=[%016llx]\n", kind, data);
}

/**
 * print_pchi_trace - Print a PCHI trace
 * @a:		Printer arguments
 * @c:		Callstack
 *
 * Return: None
 */
static void
print_pchi_trace(union owl_trace trace)
{
	printf("@=[%020u] pchi=[0x%08x] priv=[%d]\n",
	       trace.lsb_timestamp, trace.pchi.pchi, trace.pchi.priv);
}

static printfn_t default_print_trace[8] = {
	[OWL_TRACE_KIND_UECALL]		= print_ecall_trace,
	[OWL_TRACE_KIND_RETURN]		= print_return_trace,
	[OWL_TRACE_KIND_SECALL]		= print_ecall_trace,
	[OWL_TRACE_KIND_TIMESTAMP]	= print_timestamp_trace,
	[OWL_TRACE_KIND_EXCEPTION]	= print_exception_trace,
	[OWL_TRACE_KIND_PCHI]		= print_pchi_trace,
	[6]				= print_invalid_trace,
	[7]				= print_invalid_trace,
};

static struct printer default_printer = {
	.print_trace = default_print_trace,
};

/* End default output format */

struct options {
	enum { OUTFMT_NORMAL, OUTFMT_FLAME, OUTFMT_KUTRACE_EVENT } outfmt;
	bool verbose;
	const char *input;
	bool have_cpu;
	int cpu;
	const char *sysroot;
	float clock_freq;
};

/**
 * count_traces - Count the number of traces in a raw trace buffer
 *
 * @tracebuf:		Raw trace buffer
 * @tracebuf_size:	Number of traces
 * @ntraces:		Pointer to store number of traces
 * @npchitraces:	Pointer to store number of PCHI traces
 *
 * Return: None.
 */
static void
count_traces(const uint8_t *tracebuf, size_t tracebuf_size, size_t *ntraces)
{
	union owl_trace trace;
	size_t n = 0, npchi = 0, i = 0;

	while (true) {
		memcpy(&trace, &tracebuf[i], min(8, tracebuf_size - i));
		if (i >= tracebuf_size)
			break;
		assert(owl_trace_valid_p(trace));
		i += owl_trace_size(trace);
		if (i > tracebuf_size) {
			/* Edge case: H/W packs data in 64-bit chunks before
			 * written to memory. It is thus possible that the last
			 * emitted trace could be chopped in half and is
			 * incomplete. If so, ignore it. */
			break;
		}
		n++;
		if (trace.kind == OWL_TRACE_KIND_PCHI)
			npchi++;
	}
	*ntraces = n;
}

/* Timestamp and tie each trace to a task */
static void
preprocess_traces(union owl_trace *out, const uint8_t *tracebuf,
		  size_t tracebuf_size, size_t n)
{
	size_t i, offs = 0;
	union owl_trace trace;

	for (i = 0; i < n; i++, offs += owl_trace_size(trace)) {
		memcpy(&trace, &tracebuf[offs], min(8, tracebuf_size - offs));
		out[i] = trace;
	}
}

static void
dump_trace_one_cpu(const uint8_t *trace_stream, size_t trace_stream_size,
		   struct printer *printer)
{
	size_t ntraces, i;
	union owl_trace *traces;

	/* Count number of traces */
	count_traces(trace_stream, trace_stream_size, &ntraces);
	if (!ntraces)
		return;

	traces = calloc(ntraces, sizeof(*traces));

	preprocess_traces(traces, trace_stream, trace_stream_size, ntraces);

	/* The first trace should be a timestamp. */
	ERROR_ON(traces[0].kind != OWL_TRACE_KIND_TIMESTAMP,
		 "%s", "First trace is not a timestamp!\n");

	for (i = 0; i < ntraces; i++)
		printer->print_trace[traces[i].kind](traces[i]);

	free(traces);
}

static void
dump_trace(const uint8_t *tracebuf, size_t tracebuf_size, struct printer *printer)
{
	dump_trace_one_cpu(tracebuf, tracebuf_size, printer);
}

static int
map_file(const char *path, const void **ptr, size_t *size)
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

	mem = mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED)
		return -1;

	*ptr = mem;
	*size = sb.st_size;

	return fd;
}

static void __attribute__((noreturn))
print_usage_and_die(int argc, char **argv, int retval)
{
	FILE *f;

	(void)argc;

	f = retval == EXIT_SUCCESS ? stdout : stderr;
	fprintf(f,
		"usage: %s [--verbose | -v] [[--format | -f] [normal | flame | kutrace]] [[--cpu | -c] cpu] [[--sysroot | -s] sysroot] [[--clock-freq | -F] clockfreq] [--help | -h] FILE\n",
		argv[0]);

	exit(retval);
}

static void
parse_options_or_die(int argc, char **argv, struct options *options)
{
	int c;

	if (argc < 2)
		print_usage_and_die(argc, argv, EXIT_FAILURE);

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"verbose", no_argument,       NULL,  'v' },
			{"format",  required_argument, NULL,  'f' },
			{"cpu",     required_argument, NULL,  'c' },
			{"clock-freq", required_argument, NULL, 'F' },
			{"sysroot", required_argument, NULL,  's' },
			{"help",    no_argument,       NULL,  'h' },
			{0,         0,                 NULL,  0   }
		};

		c = getopt_long(argc, argv, "vf:c:F:s:h", long_options,
				&option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'v':
				options->verbose = true;
				break;
			case 'f':
				if (!STRNCMP_LIT(optarg, "normal")) {
					options->outfmt = OUTFMT_NORMAL;
					break;
				}
				if (!STRNCMP_LIT(optarg, "flame")) {
					options->outfmt = OUTFMT_FLAME;
					break;
				}
				if (!STRNCMP_LIT(optarg, "kutrace")) {
					options->outfmt = OUTFMT_KUTRACE_EVENT;
					break;
				}
				print_usage_and_die(argc, argv, EXIT_FAILURE);
				break;
			case 'c':
				options->have_cpu = true;
				options->cpu = (int) strtol(optarg, NULL, 0);
				break;
			case 'F':
				options->clock_freq =
					(float) strtol(optarg, NULL, 0);
				break;
			case 's':
				options->sysroot = optarg;
				break;
			case 'h':
				print_usage_and_die(argc, argv, EXIT_SUCCESS);
				break;
			case 0:
				/* We don't have any long opts without short
				 * variants.
				 * NB: Review when adding more options. */
				abort();
				break;

			case '?': /* Unknown option */
			default:
				print_usage_and_die(argc, argv, EXIT_FAILURE);
		}
	}

	if (optind >= argc)
		print_usage_and_die(argc, argv, EXIT_FAILURE);
	options->input = argv[optind];
	optind++;

	if (optind != argc)
		print_usage_and_die(argc, argv, EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	const uint8_t *buf, *tracebuf, *payload;
	int fd;
	size_t buf_size, tracebuf_size;
	struct options options = { 0, .clock_freq = 100000000.0f };
	struct printer *printer;

	/* Disable line buffering */
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	parse_options_or_die(argc, argv, &options);
	stdwarn = options.outfmt == OUTFMT_NORMAL ? stdout : stderr;

	fd = map_file(options.input, (const void **) &buf, &buf_size);
	if (fd < 0) {
		perror(argv[0]);
		print_usage_and_die(argc, argv, EXIT_FAILURE);
	}

	payload = (const uint8_t *) buf;
	tracebuf = payload;
	tracebuf_size = buf_size;

	printer = &default_printer;

	dump_trace(tracebuf, tracebuf_size, printer);

	munmap((void *) buf, buf_size);
	close(fd);

	return 0;
}
