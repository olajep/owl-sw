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
	union owl_trace enter_trace;
	union owl_trace return_trace;
	uint64_t enter_time;
	uint64_t exit_time;
	/* We could have a task switch ?!?! */
	/* const struct owl_metadata_entry *current_task; */
	uint32_t pchi;
};

struct callstack {
	struct call_frame *frames;
	int from_frame;	/* The current 'frame' we're at in the callstack */
	int to_frame;	/* The 'frame' we're going to */
};

struct print_args {
	/* Used for timestamp pchi & invalid */
	union owl_trace trace;
	uint64_t absclocks;

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
full_pc(uint32_t pclo, uint32_t pchi, unsigned pc_bits,
	bool sign_extend)
{
	uint64_t pc;
	assert(pc_bits > 32 && "Support =<32 bit addresses");

	if (sign_extend)
		pchi = sign_extend_pchi(pchi, pc_bits);
	pc = (((uint64_t) pchi) << 32) | pclo;

	return pc;
}

struct call_frame *
parent_frame(struct callstack *c)
{
	int parent = min(c->to_frame, c->from_frame);
	return &c->frames[parent];
}

struct call_frame *
this_frame(struct callstack *c)
{
	int frame = max(c->to_frame, c->from_frame);
	assert(0 <= c->to_frame && c->to_frame < 3);
	assert(0 <= c->from_frame && c->from_frame < 3);
	return &c->frames[frame];
}

const char *
return_type(struct call_frame *frame)
{
	switch (frame->enter_trace.kind) {
	case OWL_TRACE_KIND_UECALL: return "eret ";
	case OWL_TRACE_KIND_SECALL: return "mret ";
	case OWL_TRACE_KIND_EXCEPTION:
		if (frame->enter_trace.exception.cause & 128)
			return "iret ";
		else
			return "exret";
	default:
		printf("return trace kind=%d\n", frame->enter_trace.kind);
		assert("wrong return trace" && 0);
		return "?????";
	}
}

const char *
binary_name(struct print_args *a, struct callstack *c,
	    uint64_t *pc, uint64_t *offset)
{
	struct call_frame *parent = parent_frame(c);

	*pc = full_pc(parent->return_trace.ret.pc, parent->pchi, a->pc_bits,
		      a->sign_extend_pc);
	*offset = *pc;

	const char *binary = "'none'";
	if (c->to_frame == 0) {
		struct owl_map_info *map;
		struct map_search_key key = {
			.pid = a->current_task->pid,
			.pc = *pc
		};

		assert(parent->enter_trace.kind == OWL_TRACE_KIND_UECALL ||
		       parent->enter_trace.kind == OWL_TRACE_KIND_EXCEPTION);

		/* Detecting when we should use the parent's memory mapping
		 * seems fragile. We might have to add timestamping to the
		 * mmaping metadata to detect whether the region is alive at
		 * this point in time. */
		if (a->current_task->in_execve)
			key.pid = a->current_task->ppid;
		map = find_map(&key, a->maps, a->num_map_entries);
		if (!map && !a->current_task->has_mm) {
			key.pid = a->current_task->ppid;
			map = find_map(&key, a->maps, a->num_map_entries);
		}

		if (map) {
			binary = map->path;
			*offset = *pc - map->vm_start;
		} else
			binary = "'none'";
	} else if (c->to_frame == 1) {
		binary = "'vmlinux'";
		/* offset = a->frame[a->to_frame].ret.pc |
		 * 		$(objdump -f vmlinux | grep "start address) */
	}
	assert(c->to_frame < 2);

	return binary;
}

void
describe_exception(union owl_trace trace, const char **type, const char **name,
		   const char **desc, unsigned *cause)
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

/* End print helper functions */

static void
print_nop(struct print_args *a, struct callstack *c)
{
	(void)a;
	(void)c;
}

/* Begin default output format */

static void
print_uecall_trace(struct print_args *a, struct callstack *c)
{
	struct call_frame *frame = this_frame(c);
	/* TODO: Support hcall if we add support for it in H/W */
	printf("@=[%020llu] ecall\t\tfunction=[%05d]%c",
	       (llu_t) frame->enter_time, frame->enter_trace.ecall.regval,
	       a->delim);
}

static void
print_secall_trace(struct print_args *a, struct callstack *c)
{
	struct call_frame *frame = this_frame(c);
	/* TODO: Support hcall if we add support for it in H/W */
	printf("@=[%020llu] mcall\t\tfunction=[%05d]%c",
	       (llu_t) frame->enter_time, frame->enter_trace.ecall.regval,
	       a->delim);
}

static void
print_return_trace(struct print_args *a, struct callstack *c)
{
	/* TODO: Support hcall if we add support for it in H/W */
	/* TODO: Print time delta */
	const char *type;
	uint64_t pc, offset;
	const char *binary = "'none'";
	struct call_frame *parent = parent_frame(c);

	pc = full_pc(parent->return_trace.ret.pc, parent->pchi,
		     a->pc_bits, a->sign_extend_pc);
	offset = pc;

	type = return_type(this_frame(c));
	binary = binary_name(a, c, &pc, &offset);

	printf("@=[%020llu] %s\t\tpc=[%016llx] retval=[%05d] file=[%s+0x%llx]%c",
	       (llu_t) parent->exit_time, type,
	       (llu_t) pc, parent->return_trace.ret.regval, binary,
	       (llu_t) offset, a->delim);
}

static void
print_exception_trace(struct print_args *a, struct callstack *c)
{
	const char *type, *name, *desc;
	unsigned cause;
	struct call_frame *frame = this_frame(c);

	describe_exception(frame->enter_trace, &type, &name, &desc, &cause);

	printf("@=[%020llu] %s\t%s=[0x%03x] name=%s%c",
	       (llu_t) frame->enter_time, type, desc, cause, name, a->delim);
}

static void
print_timestamp_trace(struct print_args *a, struct callstack *c)
{
	(void)c;
	assert(a->absclocks == a->trace.timestamp.timestamp);
	printf("@=[%020llu] timestamp\tt=[%020llu]%c",
	       (llu_t) a->absclocks, (llu_t) a->trace.timestamp.timestamp,
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
	       (llu_t) a->absclocks, pchi, a->trace.pchi.priv, a->delim);
}

static printfn_t default_print_trace[8] = {
	[OWL_TRACE_KIND_UECALL]		= print_uecall_trace,
	[OWL_TRACE_KIND_RETURN]		= print_return_trace,
	[OWL_TRACE_KIND_SECALL]		= print_secall_trace,
	[OWL_TRACE_KIND_TIMESTAMP]	= print_nop,
	[OWL_TRACE_KIND_EXCEPTION]	= print_exception_trace,
	[OWL_TRACE_KIND_PCHI]		= print_nop,
	[6]				= print_invalid_trace,
	[7]				= print_invalid_trace,
};

static printfn_t default_verbose_print_trace[8] = {
	[OWL_TRACE_KIND_UECALL]		= print_uecall_trace,
	[OWL_TRACE_KIND_RETURN]		= print_return_trace,
	[OWL_TRACE_KIND_SECALL]		= print_secall_trace,
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
flame_recurse_callgraph(struct print_args *orig_args, struct callstack *orig_c)
{
	struct print_args a;
	struct callstack c;
	int i;

	memcpy(&a, orig_args, sizeof(a));
	memcpy(&c, orig_c, sizeof(c));

	a.delim = ';';
	printf("%s/%d%c",
	       a.current_task->comm, a.current_task->pid, a.delim);
	for (i = 0; i < orig_c->from_frame; i++) {
		c.to_frame = i;
		real_print_flame_trace[this_frame(&c)->enter_trace.kind](&a, &c);
	}
	a.delim = ' ';
	c.to_frame = orig_c->to_frame;
	real_print_flame_trace[this_frame(&c)->enter_trace.kind](&a, &c);
	a.delim = orig_args->delim;
	printf("%llu%c", (llu_t) a.absclocks, a.delim);
}

static void
print_flame_uecall_trace(struct print_args *a, struct callstack *c)
{
	printf("syscall/%d%c", this_frame(c)->enter_trace.ecall.regval,
	       a->delim);
}

static void
print_flame_secall_trace(struct print_args *a, struct callstack *c)
{
	printf("mcall/%d%c", this_frame(c)->enter_trace.ecall.regval,
	       a->delim);
}

static void
print_flame_return_trace(struct print_args *a, struct callstack *c)
{
	/* TODO: Support hcall if we add support for it in H/W */
	/* TODO: Print time delta */
	const char *type; /* Type of return */
	uint64_t pc, offset;
	const char *binary = "'none'";
	struct call_frame *parent = parent_frame(c);

	type = return_type(parent);
	binary = binary_name(a, c, &pc, &offset);

	printf("%s\t\tpc=[%016llx] retval=[%05d] file=[%s+0x%llx]%c",
	       type, (llu_t) pc, parent->return_trace.ret.regval,
	       binary, (llu_t) offset, a->delim);
}

static void
print_flame_exception_trace(struct print_args *a, struct callstack *c)
{
	const char *type, *name, *desc;
	unsigned cause;
	struct call_frame *frame = this_frame(c);

	describe_exception(frame->enter_trace, &type, &name, &desc, &cause);

	printf("%s/%s%c",
	       type, name, a->delim);
}

static printfn_t print_flame_trace[8] = {
	[OWL_TRACE_KIND_UECALL]		= flame_recurse_callgraph,
	[OWL_TRACE_KIND_RETURN]		= flame_recurse_callgraph,
	[OWL_TRACE_KIND_SECALL]		= flame_recurse_callgraph,
	[OWL_TRACE_KIND_TIMESTAMP]	= flame_recurse_callgraph,
	[OWL_TRACE_KIND_EXCEPTION]	= flame_recurse_callgraph,
	[OWL_TRACE_KIND_PCHI]		= flame_recurse_callgraph,
	[6]				= flame_recurse_callgraph,
	[7]				= flame_recurse_callgraph,
};
static printfn_t real_print_flame_trace[8] = {
	[OWL_TRACE_KIND_UECALL]		= print_flame_uecall_trace,
	[OWL_TRACE_KIND_RETURN]		= print_flame_return_trace,
	[OWL_TRACE_KIND_SECALL]		= print_flame_secall_trace,
	[OWL_TRACE_KIND_TIMESTAMP]	= print_nop,
	[OWL_TRACE_KIND_EXCEPTION]	= print_flame_exception_trace,
	[OWL_TRACE_KIND_PCHI]		= print_nop,
	[6]				= print_invalid_trace,
	[7]				= print_invalid_trace,
};

/* End FlameChart friendly output format */

void
print_metadata(const struct owl_metadata_entry *entry, uint64_t absclocks, char delim)
{
	assert(entry->comm[OWL_TASK_COMM_LEN - 1] == '\0');
	printf("@=[%020llu] sched\t\tcomm=[%s] pid=[%05d] until=[%020llu] cpu=[%d]%c",
	       (llu_t) absclocks,  entry->comm, entry->pid,
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

uint32_t
find_pchi(const uint8_t *tracebuf, size_t i, size_t tracebuf_size, int to_frame,
	   uint32_t pchi)
{
	union owl_trace trace, from;

	memcpy(&from, &tracebuf[i], min(8, tracebuf_size - i));
	for (; i < tracebuf_size; i += owl_trace_size(trace)) {
		memcpy(&trace, &tracebuf[i], min(8, tracebuf_size - i));

		/* HACK: We should be able to get the exact size from the
		   driver.  */
		if (owl_trace_empty_p(trace))
			break;

		/* A PCHI trace will be close to the normal return trace.
		 * Support edge case where a timestamp trace is emitted in
		 * between the traces. */
		if (trace.lsb_timestamp != from.lsb_timestamp &&
		    trace.lsb_timestamp != ((from.lsb_timestamp + 1) & 0x3ffff))
			break;

		if (trace.kind == OWL_TRACE_KIND_PCHI) {
			assert(trace.pchi.priv == to_frame);
			return trace.pchi.pchi;
		}
	}
	return pchi;
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
	uint32_t pchi = 0;
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

	/* Initialize with sane values */
	call_frame[0].enter_trace.kind = OWL_TRACE_KIND_UECALL;
	call_frame[1].enter_trace.kind = OWL_TRACE_KIND_UECALL;
	call_frame[2].enter_trace.kind = OWL_TRACE_KIND_SECALL;
	call_frame[0].return_trace.kind = OWL_TRACE_KIND_RETURN;
	call_frame[1].return_trace.kind = OWL_TRACE_KIND_RETURN;
	call_frame[2].return_trace.kind = OWL_TRACE_KIND_RETURN;
	/* call_frame[0].current_task = current_task; */

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
			if (trace.kind == OWL_TRACE_KIND_RETURN) {
				to_frame--;
				/* H/W writes the PCHI trace after the normal
				 * trace so we need to look forward in the
				 * buffer to find it. */
				pchi = find_pchi(tracebuf, i, tracebuf_size,
						 to_frame,
						 call_frame[to_frame].pchi);
				call_frame[to_frame].pchi = pchi;
				call_frame[to_frame].return_trace = trace;
				call_frame[to_frame].exit_time = absclocks;
			} else {
				to_frame++;
				/* call_frame[to_frame].current_task = current_task; */
				call_frame[to_frame].enter_time = absclocks;
				call_frame[to_frame].enter_trace = trace;
			}
		}
		assert(0 <= to_frame && to_frame < 3);
		assert(0 <= from_frame && from_frame < 3);

		{
			struct print_args args = {
				.trace			= trace,
				.absclocks		= absclocks,
				.maps			= maps,
				.num_map_entries	= num_map_entries,
				.current_task		= current_task,
				.pc_bits		= 39,
				.sign_extend_pc		= true,
				.delim			= '\n'
			};
			struct callstack callstack = {
				.frames			= call_frame,
				.from_frame		= from_frame,
				.to_frame		= to_frame,
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
