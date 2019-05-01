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
#include <stdbool.h>
#include <getopt.h>

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

#define STRNCMP_LIT(s, lit) strncmp((s), ""lit"", sizeof((lit)-1))

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

struct call_frame {
	union owl_trace enter_trace;  /* Trace entering this frame */
	union owl_trace return_trace; /* Trace returning to this frame */
	uint64_t enter_time;
	uint64_t return_time;
	/* We could have a task switch ?!?! */
	const struct owl_metadata_entry *enter_task;
	const struct owl_metadata_entry *return_task;
	uint32_t pchi;
};

struct callstack {
	struct call_frame *frames;
	int frameno; /* The 'frame' we're at */
};

struct print_args {
	/* Used for timestamp pchi & invalid */
	union owl_trace trace;
	uint64_t timestamp;

	/* Current task and memory mapping info */
	const struct owl_map_info *maps;
	size_t num_map_entries;
	const struct owl_metadata_entry *current_task;

	/* Arch settings */
	unsigned pc_bits;
	bool sign_extend_pc;

	char delim;
};

struct map_search_key {
	int pid;
	uint64_t pc;
};

typedef void (* const printfn_t)(struct print_args *, struct callstack *);

/* Begin print helper functions */

struct owl_map_info *find_map(const struct map_search_key *key,
			      const struct owl_map_info *maps,
			      size_t num_map_entries);

uint32_t
sign_extend_pchi(uint32_t pchi, unsigned pc_bits)
{
	unsigned sign_bits = pc_bits - 32;
	pchi &= ((1 << sign_bits) - 1);
	if (pchi & (1ULL << (sign_bits - 1)))
		pchi = (~0ULL ^ ((1 << sign_bits) - 1)) | pchi;

	return pchi;
}

uint64_t
full_pc(struct call_frame *frame, unsigned pc_bits,
	bool sign_extend)
{
	uint32_t pclo, pchi;
	uint64_t pc;

	pclo = frame->return_trace.ret.pc;
	pchi = frame->pchi;

	assert(pc_bits > 32 && "Support =<32 bit addresses");

	if (sign_extend)
		pchi = sign_extend_pchi(pchi, pc_bits);
	pc = (((uint64_t) pchi) << 32) | pclo;

	return pc;
}

static int
this_frameno(struct callstack *c)
{
	return c->frameno;
}

static struct call_frame *
this_frame(struct callstack *c)
{
	assert (0 <= c->frameno && c->frameno <= 2);
	return &c->frames[c->frameno];
}

static struct call_frame *
frame_down(struct callstack *c)
{
	assert (0 <= c->frameno && c->frameno < 2);
	return &c->frames[c->frameno + 1];
}

static struct call_frame *
frame_up(struct callstack *c)
{
	assert (1 <= c->frameno && c->frameno <= 2);
	return &c->frames[c->frameno - 1];
}

const char *
return_type(struct call_frame *frame)
{
	switch (frame->enter_trace.kind) {
	case OWL_TRACE_KIND_UECALL: return "eret";
	case OWL_TRACE_KIND_SECALL: return "mret";
	case OWL_TRACE_KIND_EXCEPTION:
		if (frame->enter_trace.exception.cause & 128)
			return "iret";
		else
			return "exret";
	default:
		printf("enter trace kind=%d\n", frame->enter_trace.kind);
		assert("wrong return trace" && 0);
		return "?????";
	}
}

const char *
binary_name(struct print_args *a, struct callstack *c, uint64_t *pc,
	    uint64_t *offset)
{
	const struct owl_metadata_entry *task = this_frame(c)->return_task;
	*pc = full_pc(this_frame(c), a->pc_bits, a->sign_extend_pc);
	*offset = *pc;

	const char *binary = "'none'";
	if (this_frameno(c) == 0) {
		struct owl_map_info *map;
		struct map_search_key key = {
			.pid = task->pid,
			.pc = *pc
		};

		assert(frame_down(c)->enter_trace.kind == OWL_TRACE_KIND_UECALL ||
		       frame_down(c)->enter_trace.kind == OWL_TRACE_KIND_EXCEPTION);

		/* Detecting when we should use the parent's memory mapping
		 * seems fragile. We might have to add timestamping to the
		 * mmaping metadata to detect whether the region is alive at
		 * this point in time. */
		if (task->in_execve)
			key.pid = task->ppid;
		map = find_map(&key, a->maps, a->num_map_entries);
		if (!map && !task->has_mm) {
			key.pid = task->ppid;
			map = find_map(&key, a->maps, a->num_map_entries);
		}

		if (map) {
			binary = map->path;
			*offset = *pc - map->vm_start;
		} else
			binary = "'none'";
	} else if (this_frameno(c) == 1) {
		assert(frame_down(c)->enter_trace.kind == OWL_TRACE_KIND_SECALL ||
		       frame_down(c)->enter_trace.kind == OWL_TRACE_KIND_EXCEPTION);
		binary = "'vmlinux'";
		/* offset = a->frame[a->to_frame].ret.pc |
		 * 		$(objdump -f vmlinux | grep "start address) */
	}
	assert(this_frameno(c) < 2);

	return binary;
}

void
describe_exception_frame(struct call_frame *frame, const char **type,
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

	*cause = frame->enter_trace.exception.cause;
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

void
describe_frame_enter(struct call_frame *frame, const char **type,
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

	switch (frame->enter_trace.kind) {
	case OWL_TRACE_KIND_UECALL:
		*type = "ecall";
		*cause = frame->enter_trace.ecall.regval;
		break;
	case OWL_TRACE_KIND_SECALL:
		*type = "mcall";
		*cause = frame->enter_trace.ecall.regval;
		break;
	case OWL_TRACE_KIND_EXCEPTION:
		describe_exception_frame(frame, type, name, desc, cause);
		break;
	default:
		assert(0 && "Wrong trace kind\n");
	}
}

/* End print helper functions */

static void
print_nop(struct print_args *a, struct callstack *c)
{
	(void)a;
	(void)c;
}

/* Begin default output format */

static void
print_ecall_trace(struct print_args *a, struct callstack *c)
{
	const char *type;
	unsigned function;

	describe_frame_enter(this_frame(c), &type, NULL, NULL, &function);
	/* TODO: Support hcall if we add support for it in H/W */
	printf("@=[%020llu] %s\t\tfunction=[%05d]%c",
	       (llu_t) this_frame(c)->enter_time, type, function, a->delim);
}

static void
print_return_trace(struct print_args *a, struct callstack *c)
{
	/* TODO: Support hcall if we add support for it in H/W */
	/* TODO: Print time delta */
	const char *type;
	uint64_t pc, offset;
	const char *binary = "'none'";

	pc = full_pc(this_frame(c), a->pc_bits, a->sign_extend_pc);
	offset = pc;

	type = return_type(frame_down(c));
	binary = binary_name(a, c, &pc, &offset);

	printf("@=[%020llu] %-5s\t\tpc=[%016llx] retval=[%05d] file=[%s+0x%llx]%c",
	       (llu_t) this_frame(c)->return_time, type,
	       (llu_t) pc, this_frame(c)->return_trace.ret.regval, binary,
	       (llu_t) offset, a->delim);
}

static void
print_exception_trace(struct print_args *a, struct callstack *c)
{
	const char *type, *name, *desc;
	unsigned cause;

	describe_frame_enter(this_frame(c), &type, &name, &desc, &cause);
	printf("@=[%020llu] %s\t%s=[0x%03x] name=%s%c",
	       (llu_t) this_frame(c)->enter_time, type, desc, cause, name,
	       a->delim);
}

static void
print_timestamp_trace(struct print_args *a, struct callstack *c)
{
	(void)c;
	assert(a->timestamp == a->trace.timestamp.timestamp);
	printf("@=[%020llu] timestamp\tt=[%020llu]%c",
	       (llu_t) a->timestamp, (llu_t) a->trace.timestamp.timestamp,
	       a->delim);
}

static void
print_invalid_trace(struct print_args *a, struct callstack *c)
{
	(void)c;
	long long data;
	unsigned kind = a->trace.kind;
	memcpy(&data, &a->trace, sizeof(data));
	printf("INVALID TRACE kind=%u data=[%016llx]%c", kind, data, a->delim);
}

static void
print_pchi_trace(struct print_args *a, struct callstack *c)
{
	(void)c;
	uint32_t pchi = a->trace.pchi.pchi;
	if (a->sign_extend_pc)
		pchi = sign_extend_pchi(pchi, a->pc_bits);
	printf("@=[%020llu] pchi=[0x%08x] priv=[%d]%c",
	       (llu_t) a->timestamp, pchi, a->trace.pchi.priv, a->delim);
}

static printfn_t default_print_trace[8] = {
	[OWL_TRACE_KIND_UECALL]		= print_ecall_trace,
	[OWL_TRACE_KIND_RETURN]		= print_return_trace,
	[OWL_TRACE_KIND_SECALL]		= print_ecall_trace,
	[OWL_TRACE_KIND_TIMESTAMP]	= print_nop,
	[OWL_TRACE_KIND_EXCEPTION]	= print_exception_trace,
	[OWL_TRACE_KIND_PCHI]		= print_nop,
	[6]				= print_invalid_trace,
	[7]				= print_invalid_trace,
};

static printfn_t default_verbose_print_trace[8] = {
	[OWL_TRACE_KIND_UECALL]		= print_ecall_trace,
	[OWL_TRACE_KIND_RETURN]		= print_return_trace,
	[OWL_TRACE_KIND_SECALL]		= print_ecall_trace,
	[OWL_TRACE_KIND_TIMESTAMP]	= print_timestamp_trace,
	[OWL_TRACE_KIND_EXCEPTION]	= print_exception_trace,
	[OWL_TRACE_KIND_PCHI]		= print_pchi_trace,
	[6]				= print_invalid_trace,
	[7]				= print_invalid_trace,
};

/* End default output format */

/* Begin FlameChart friendly output format */

/* FlameChart friendly output
 * NB: For simplicity we only output the timestamp here, and not the duration.
 * Post process with script */

static printfn_t print_flame_trace[8];
static printfn_t real_print_flame_trace[8];

static void
flame_recurse_down(struct print_args *a, struct callstack *c, int level)
{
	const bool terminate = c->frameno == level;

	a->delim = ';';
	real_print_flame_trace[this_frame(c)->enter_trace.kind](a, c);
	if (terminate) {
		/* TODO: Print time delta */
		printf("%llu\n", (llu_t) this_frame(c)->enter_time);
		return;
	}

	c->frameno++;
	flame_recurse_down(a, c, level);
}

static void
flame_recurse_up(struct print_args *a, struct callstack *c, int level)
{
	const bool terminate = c->frameno == level;

	a->delim = ';';
	if (terminate) {
		real_print_flame_trace[this_frame(c)->return_trace.kind](a, c);
		/* TODO: Print time delta */
		printf("%llu\n", (llu_t) this_frame(c)->return_time);
		return;
	} else {
		c->frameno++;
		real_print_flame_trace[this_frame(c)->enter_trace.kind](a, c);
		c->frameno--;
	}

	c->frameno++;
	flame_recurse_up(a, c, level);
}

static void
flame_recurse_callgraph(struct print_args *orig_a, struct callstack *orig_c)
{
	struct print_args a;
	struct callstack c;

	a = *orig_a;
	c = *orig_c;

	printf("%s/%d;",
	       orig_c->frames[0].return_task->comm,
	       orig_c->frames[0].return_task->pid);
	if (orig_a->trace.kind != OWL_TRACE_KIND_RETURN) {
		c.frameno = 1;
		flame_recurse_down(&a, &c, orig_c->frameno);
	} else {
		c.frameno = 0;
		flame_recurse_up(&a, &c, orig_c->frameno);
	}
}

static void
print_flame_enter_trace(struct print_args *a, struct callstack *c)
{
	const char *type;
	unsigned cause;

	describe_frame_enter(this_frame(c), &type, NULL, NULL, &cause);

	c->frameno--;
	real_print_flame_trace[this_frame(c)->return_trace.kind](a, c);
	c->frameno++;

	if (this_frame(c)->enter_trace.kind == OWL_TRACE_KIND_EXCEPTION) {
		printf("%s/%d%c", type, cause, a->delim);
	} else {
		printf("%s/%d=%d%c", type, cause,
		       frame_up(c)->return_trace.ret.regval, a->delim);
	}
}

static void
print_flame_return_trace(struct print_args *a, struct callstack *c)
{
	/* TODO: Support hcall if we add support for it in H/W */
	uint64_t pc, offset;
	const char *binary = "'none'";

	pc = full_pc(this_frame(c), a->pc_bits, a->sign_extend_pc);
	offset = pc;
	binary = binary_name(a, c, &pc, &offset);

	printf("%s+0x%llx%c", binary, (llu_t) offset, a->delim);
}

static printfn_t print_flame_trace[8] = {
	[OWL_TRACE_KIND_UECALL]		= flame_recurse_callgraph,
	[OWL_TRACE_KIND_RETURN]		= flame_recurse_callgraph,
	[OWL_TRACE_KIND_SECALL]		= flame_recurse_callgraph,
	[OWL_TRACE_KIND_TIMESTAMP]	= print_nop,
	[OWL_TRACE_KIND_EXCEPTION]	= flame_recurse_callgraph,
	[OWL_TRACE_KIND_PCHI]		= print_nop,
	[6]				= print_invalid_trace,
	[7]				= print_invalid_trace,
};
static printfn_t real_print_flame_trace[8] = {
	[OWL_TRACE_KIND_UECALL]		= print_flame_enter_trace,
	[OWL_TRACE_KIND_RETURN]		= print_flame_return_trace,
	[OWL_TRACE_KIND_SECALL]		= print_flame_enter_trace,
	[OWL_TRACE_KIND_TIMESTAMP]	= print_nop,
	[OWL_TRACE_KIND_EXCEPTION]	= print_flame_enter_trace,
	[OWL_TRACE_KIND_PCHI]		= print_nop,
	[6]				= print_invalid_trace,
	[7]				= print_invalid_trace,
};

/* End FlameChart friendly output format */

void
print_metadata(const struct owl_metadata_entry *entry, uint64_t timestamp, char delim)
{
	assert(entry->comm[OWL_TASK_COMM_LEN - 1] == '\0');
	printf("@=[%020llu] sched\t\tcomm=[%s] pid=[%05d] until=[%020llu] cpu=[%d]%c",
	       (llu_t) timestamp, entry->comm, entry->pid,
	       (llu_t) entry->timestamp, (int) entry->cpu, delim);
}

int find_compare_maps(const void *_key, const void *_elem)
{
	const struct map_search_key *key = _key;
	const struct owl_map_info *elem = _elem;

	if (key->pid < elem->pid)
		return -1;
	if (key->pid > elem->pid)
		return 1;

	if (key->pc < elem->vm_start)
		return -1;
	if (key->pc > elem->vm_end)
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

static void
try_find_pchi(const uint8_t *tracebuf, size_t i, size_t tracebuf_size,
	      struct call_frame *frame)
{
	union owl_trace trace, from;

	//printf("i=%llu\n", (llu_t) i);

	memcpy(&from, &tracebuf[i], min(8, tracebuf_size - i));
	for (; i < tracebuf_size; i += owl_trace_size(trace)) {
		memcpy(&trace, &tracebuf[i], min(8, tracebuf_size - i));

		/* HACK: We should be able to get the exact size from the
		   driver.  */
		if (owl_trace_empty_p(trace))
			return;

		/* A PCHI trace will be close to the normal return trace.
		 * Support edge case where a timestamp trace is emitted in
		 * between the traces. */
		if (trace.lsb_timestamp != from.lsb_timestamp &&
		    trace.lsb_timestamp != ((from.lsb_timestamp + 1) & 0x3ffff))
			return;

		if (trace.kind == OWL_TRACE_KIND_PCHI) {
			/* assert(trace.pchi.priv == to_frame); */
			frame->pchi = trace.pchi.pchi;
			return;
		}
	}
}

/* TODO: Check options. This isn't needed for the default output format. */
static void
try_populate_frame(const uint8_t *tracebuf, size_t i, size_t tracebuf_size,
		   struct call_frame *frame)
{
	union owl_trace trace;
	union owl_trace return_trace = { .kind = OWL_TRACE_KIND_RETURN, 0 };
	int rel_frame = 0;
	bool found = false;

	while (i < tracebuf_size) {
		memcpy(&trace, &tracebuf[i], min(8, tracebuf_size - i));

		/* HACK: We should be able to get the exact size from the
		   driver.  */
		if (owl_trace_empty_p(trace)) {
			frame->return_trace = return_trace;
			break;
		}

		switch (trace.kind) {
		case OWL_TRACE_KIND_EXCEPTION:
		case OWL_TRACE_KIND_UECALL:
		case OWL_TRACE_KIND_SECALL:
			rel_frame++;
			break;
		case OWL_TRACE_KIND_RETURN:
			rel_frame--;
			if (rel_frame == 0) {
				return_trace = trace;
				found = true;
			}
			break;
		}

		if (found)
			break;

		i += owl_trace_size(trace);
	}

	frame->return_trace = return_trace;
	assert(found);

	/* H/W writes the PCHI trace after the normal
	 * trace so we need to look forward in the
	 * buffer to find it. */
	try_find_pchi(tracebuf, i, tracebuf_size, frame);
}

struct options {
	enum { OUTFMT_NORMAL, OUTFMT_FLAME } outfmt;
	bool verbose;
	const char *input;
};

void dump_trace(const uint8_t *tracebuf, size_t tracebuf_size,
		const struct owl_metadata_entry *metadata, size_t metadata_size,
		struct owl_map_info *maps, size_t map_info_size,
		struct options *options)
{
	/* TODO: Add support for nested interrupts */

	size_t i = 0;
	const size_t num_meta_entries = metadata_size / sizeof(*metadata);
	const size_t num_map_entries = map_info_size / sizeof(*maps);
	int to_frame = 0, from_frame = 0; /* See comment about callstack/frame levels */
	union owl_trace trace, prev_timestamp = { 0 };
	struct call_frame call_frame[3] = { 0 };
	uint64_t absclocks = 0, msbclocks = 0, prev_absclocks = 0;
	uint64_t next_sched = ~0ULL;
	unsigned prev_lsb_timestamp = 0;
	const struct owl_metadata_entry *current_task = &metadata[0];
	const struct owl_metadata_entry
		*metadata_end = &metadata[num_meta_entries - 1];
	printfn_t *printfn;

	if (options->outfmt == OUTFMT_FLAME)
		printfn = print_flame_trace;
	else if (options->verbose)
		printfn = default_verbose_print_trace;
	else
		printfn = default_print_trace;

	/* Sort the map info so we can binary search it */
	sort_maps(maps, num_map_entries);

	/* Callstack/frame levels:
	 * 0: ecall <--> 1: mcall <--> 2: (interrupt or exception) */

	/* The first trace should be a timestamp. */
	memcpy(&trace, &tracebuf[0], min(8, tracebuf_size));
	ERROR_ON(trace.kind != OWL_TRACE_KIND_TIMESTAMP,
		 "%s", "First trace is not a timestamp!\n");
	i += owl_trace_size(trace);
	absclocks = trace.timestamp.timestamp;

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
			to_frame++;
		case OWL_TRACE_KIND_UECALL:
			break;
		case OWL_TRACE_KIND_RETURN:
			to_frame++;
		default: continue;
		}
		break;
	}
	from_frame = to_frame;

	/* Initialize with sane values */
	call_frame[0].enter_trace.kind = 7; /* Should never be accessed */
	call_frame[1].enter_trace.kind = OWL_TRACE_KIND_UECALL;
	call_frame[2].enter_trace.kind = OWL_TRACE_KIND_SECALL;
	call_frame[0].return_trace.kind = OWL_TRACE_KIND_RETURN;
	call_frame[1].return_trace.kind = OWL_TRACE_KIND_RETURN;
	call_frame[2].return_trace.kind = OWL_TRACE_KIND_RETURN;
	call_frame[0].enter_task = current_task;
	call_frame[1].enter_task = current_task;
	call_frame[2].enter_task = current_task;
	call_frame[0].return_task = current_task;
	call_frame[1].return_task = current_task;
	call_frame[2].return_task = current_task;
	call_frame[0].enter_time = ~0; /* Should never be accessed */
	call_frame[0].return_time  = absclocks;
	call_frame[1].enter_time = absclocks;
	call_frame[1].return_time  = absclocks;
	call_frame[2].enter_time = absclocks;
	call_frame[2].return_time  = absclocks;

	/* Print first scheduled task */
	if (current_task <= metadata_end) {
		memcpy(&trace, &tracebuf[0], min(8, tracebuf_size));
		if (options->outfmt != OUTFMT_FLAME)
			print_metadata(current_task, trace.timestamp.timestamp,
				       '\n');
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
		} else if (trace.kind != OWL_TRACE_KIND_PCHI &&
			   prev_lsb_timestamp > trace.lsb_timestamp) {
			/* Timestamp wrapped */
			msbclocks += (1ULL << 18);
		}
		absclocks = msbclocks | trace.lsb_timestamp;
		prev_lsb_timestamp = trace.lsb_timestamp;
		assert(absclocks >= prev_absclocks);
		prev_absclocks = absclocks;

		if (absclocks > next_sched) {
			if (current_task <= metadata_end) {
				if (options->outfmt != OUTFMT_FLAME)
					print_metadata(current_task, next_sched,
						       '\n');
				if (current_task < metadata_end) {
					current_task++;
					next_sched = current_task->timestamp;
				} else {
					/* Assume current_task lives until
					 * trace stops */
					next_sched = ~0ULL;
				}
			}
		}

		from_frame = to_frame;
		if (trace.kind != OWL_TRACE_KIND_TIMESTAMP &&
		    trace.kind != OWL_TRACE_KIND_PCHI) {
			/* The seemingly duplicate statements for setting up
			 * the call_frame in both if cases below are needed.
			 * Since a trace usually starts with a return trace
			 * from the tracectrl driver (level=1) and back to the
			 * user space process 'owl' (level=0), there won't be a
			 * matching ecall trace for the first return trace. */
			if (trace.kind == OWL_TRACE_KIND_RETURN) {
				to_frame--;
				/* H/W writes the PCHI trace after the normal
				 * trace so we need to look forward in the
				 * buffer to find it. */
				try_find_pchi(tracebuf, i, tracebuf_size,
					      &call_frame[to_frame]);
				call_frame[to_frame].return_trace = trace;
				call_frame[to_frame].return_time = absclocks;
				call_frame[to_frame].return_task = current_task;
			} else {
				/* Flame output need the complete frame info */
				try_populate_frame(tracebuf, i, tracebuf_size,
						   &call_frame[from_frame]);
				to_frame++;
				call_frame[to_frame].enter_task = current_task;
				call_frame[to_frame].enter_time = absclocks;
				call_frame[to_frame].enter_trace = trace;
			}
		}
		assert(0 <= to_frame && to_frame < 3);
		assert(0 <= from_frame && from_frame < 3);

		{
			struct print_args args = {
				.trace			= trace,
				.timestamp		= absclocks,
				.maps			= maps,
				.num_map_entries	= num_map_entries,
				.current_task		= current_task,
				.pc_bits		= 39,
				.sign_extend_pc		= true,
				.delim			= '\n'
			};
			struct callstack callstack = {
				.frames			= call_frame,
				.frameno		= to_frame,
			};
			printfn[trace.kind](&args, &callstack);
		}
	}
}

int map_file(const char *path, const void **ptr, size_t *size)
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

void
print_usage_and_die(int argc, char **argv, int retval)
{
	FILE *f;

	(void)argc;

	f = retval == EXIT_SUCCESS ? stdout : stderr;
	fprintf(f,
		"usage: %s [--verbose | -v] [[--format | -f] [normal | flame]] [--help | -h] FILE\n",
		argv[0]);
		exit(EXIT_FAILURE);

	exit(retval);
}

void
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
			{"help",    no_argument,       NULL,  'h' },
			{0,         0,                 NULL,  0   }
		};

		c = getopt_long(argc, argv, "vf:h", long_options, &option_index);
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
				print_usage_and_die(argc, argv, EXIT_FAILURE);
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
	const uint8_t *buf, *tracebuf;
	const struct owl_trace_file_header *file_header;
	const struct owl_metadata_entry *metadata;
	struct owl_map_info *map_info;
	int fd;
	size_t buf_size, tracebuf_size, metadata_size, map_info_size;
	struct options options = { 0 };

	/* Disable line buffering */
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	parse_options_or_die(argc, argv, &options);

	fd = map_file(options.input, (const void **) &buf, &buf_size);
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
		   map_info, map_info_size,
		   &options);

	munmap((void *) buf, buf_size);
	close(fd);

	return 0;
}
