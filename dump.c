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
#include "syscalltable.h"

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

/* A preprocessed trace with context */
struct dump_trace {
	uint64_t			timestamp;
	union owl_trace			trace;
	const struct owl_metadata_entry	*sched_info;
	const struct owl_task		*task;
	/* struct callstack ??? */
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
	union owl_trace trace;
	uint64_t timestamp;

	/* Current task and memory mapping info */
	const struct owl_map_info *maps;
	size_t num_map_entries;
	const struct owl_metadata_entry *sched_info;

	/* Arch settings */
	unsigned pc_bits;
	bool sign_extend_pc;

	char delim;
};

struct map_search_key {
	int pid;
	uint64_t pc;
};

typedef long long unsigned int llu_t;
typedef void (* const printfn_t)(struct print_args *, struct callstack *);

/* Bytes */
static size_t
owl_trace_size(union owl_trace trace)
{
	return (trace.kind & 1) ? 8 : 4;
}

/* HACK: We should be able to pull exact trace size from hardware */
static bool
owl_trace_empty_p(union owl_trace trace)
{
	const union owl_trace empty = { 0 };

	return memcmp(&trace, &empty, sizeof(empty)) == 0;
}

static bool
owl_trace_valid_addr_p(union owl_trace trace)
{
	assert(trace.kind == OWL_TRACE_KIND_RETURN);

	return !(trace.ret.pc & 1);
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

	pclo = frame->return_trace->trace.ret.pc;
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
	switch (frame->enter_trace->trace.kind) {
	case OWL_TRACE_KIND_UECALL: return "eret";
	case OWL_TRACE_KIND_SECALL: return "mret";
	case OWL_TRACE_KIND_EXCEPTION:
		if (frame->enter_trace->trace.exception.cause & 128)
			return "iret";
		else
			return "exret";
	case 7: return "switchret"; /* TODO: Have invalid flag in struct dump_trace instead */
	default:
		printf("enter trace kind=%d\n", frame->enter_trace->trace.kind);
		assert("wrong return trace" && 0);
		return "?????";
	}
}

const char *
binary_name(struct print_args *a, struct callstack *c, uint64_t *pc,
	    uint64_t *offset)
{
	const struct owl_metadata_entry *task =
		this_frame(c)->return_trace->sched_info;
	*pc = full_pc(this_frame(c), a->pc_bits, a->sign_extend_pc);
	*offset = *pc;

	/* TODO: Null check task. Output raw address in case of no scheduling
	 * info */
	const char *binary = "'none'";
	if (this_frameno(c) == 0 && !task->kthread) {
		struct owl_map_info *map;
		struct map_search_key key = {
			.pid = task->pid,
			.pc = *pc
		};

#if 0
		/* TODO: Add struct dump_trace valid flag */
		assert(frame_down(c)->enter_trace->trace.kind == OWL_TRACE_KIND_UECALL ||
		       frame_down(c)->enter_trace->trace.kind == OWL_TRACE_KIND_EXCEPTION ||
		       frame_down(c)->enter_trace->trace.kind == OWL_TRACE_KIND_SECALL);
#endif

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
#if 0
		assert(frame_down(c)->enter_trace->trace.kind == OWL_TRACE_KIND_SECALL ||
		       frame_down(c)->enter_trace->trace.kind == OWL_TRACE_KIND_EXCEPTION);
#endif
		binary = "'vmlinux'";
		/* binary = "/boot/vmlinux"; */
		/* offset = a->frame[a->to_frame].ret.pc |
		 * 		$(objdump -f vmlinux | grep "start address) */
	} else if (task->kthread) {
		binary = "'vmlinux'";
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

	*cause = frame->enter_trace->trace.exception.cause;
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

	switch (frame->enter_trace->trace.kind) {
	case OWL_TRACE_KIND_UECALL:
		*type = "ecall";
		*cause = frame->enter_trace->trace.ecall.regval;
		if (*cause >= ARRAY_SIZE(syscalltable)) {
			*name = NULL;
		} else {
			*name = syscalltable[*cause];
		}
		break;
	case OWL_TRACE_KIND_SECALL:
		*type = "mcall";
		*name = NULL;
		*cause = frame->enter_trace->trace.ecall.regval;
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
	       (llu_t) this_frame(c)->enter_trace->timestamp, type, function, a->delim);
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

#if 0
	if (this_frame(c)->return_trace->task_switch)
		type = "task_switch";
	else
#else
	if (frame_down(c)->enter_trace == NULL || frame_down(c)->enter_trace->trace.kind == 7)
		type = "scdret";
	else
#endif
		type = return_type(frame_down(c));
	binary = binary_name(a, c, &pc, &offset);

	printf("@=[%020llu] %-5s\t\tpc=[%016llx] retval=[%05d] file=[%s+0x%llx]%c",
	       (llu_t) this_frame(c)->return_trace->timestamp, type,
	       (llu_t) pc, this_frame(c)->return_trace->trace.ret.regval, binary,
	       (llu_t) offset, a->delim);
}

static void
print_exception_trace(struct print_args *a, struct callstack *c)
{
	const char *type, *name, *desc;
	unsigned cause;

	describe_frame_enter(this_frame(c), &type, &name, &desc, &cause);
	printf("@=[%020llu] %s\t%s=[0x%03x] name=%s%c",
	       (llu_t) this_frame(c)->enter_trace->timestamp, type, desc, cause, name,
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
	const bool terminate = c->frameno >= level;

	a->delim = terminate ? ' ' : ';';

	real_print_flame_trace[this_frame(c)->enter_trace->trace.kind](a, c);
	if (terminate) {
		/* TODO: Print time delta */
		printf("%llu\n", (llu_t) this_frame(c)->enter_trace->timestamp);
		return;
	}

	c->frameno++;
	flame_recurse_down(a, c, level);
}

static void
flame_recurse_up(struct print_args *a, struct callstack *c, int level)
{
	const bool terminate = c->frameno >= level;

	a->delim = terminate ? ' ' : ';';
	if (terminate) {
		real_print_flame_trace[this_frame(c)->return_trace->trace.kind](a, c);
		printf("%llu\n", (llu_t) this_frame(c)->return_trace->timestamp);
		return;
	} else {
		c->frameno++;
		real_print_flame_trace[this_frame(c)->enter_trace->trace.kind](a, c);
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
	       c.task->comm,
	       c.task->pid);
	c.frameno = 0;
	if (orig_a->trace.kind != OWL_TRACE_KIND_RETURN)
		/* TODO: Use frame?!?_?!?(c)->sched_info */
		//c.frameno = a.sched_info->kthread ? 2 : 1;
		flame_recurse_down(&a, &c, orig_c->frameno);
	else
		flame_recurse_up(&a, &c, orig_c->frameno);
}

static void
print_flame_enter_trace(struct print_args *a, struct callstack *c)
{
	const char *type = NULL, *name = NULL;
	unsigned cause;
	const char save_delim = a->delim;

	describe_frame_enter(this_frame(c), &type, &name, NULL, &cause);

	if (this_frame(c)->return_trace == NULL)
		return;

	a->delim = ';';
	c->frameno--;
	real_print_flame_trace[this_frame(c)->return_trace->trace.kind](a, c);
	c->frameno++;
	a->delim = save_delim;

	if (!name) {
		name = alloca(32);
		snprintf((char *)name, 32, "%s_[%u]", type, cause);
	}

	if (this_frame(c)->enter_trace->trace.kind == OWL_TRACE_KIND_EXCEPTION) {
		printf("%s_%s%c", type, name, a->delim);
	} else {
		printf("%s=%d%c", name,
		       frame_up(c)->return_trace->trace.ret.regval, a->delim);
	}
}

static void
print_flame_return_trace(struct print_args *a, struct callstack *c)
{
	/* TODO: Support hcall if we add support for it in H/W */
	uint64_t pc, offset;
	const char *binary = "'none'";

	if (this_frame(c)->return_trace == NULL)
		return;

	pc = full_pc(this_frame(c), a->pc_bits, a->sign_extend_pc);
	offset = pc;
	binary = binary_name(a, c, &pc, &offset);

	printf("file://%s+0x%llx%c", binary, (llu_t) offset, a->delim);
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
	[7]				= print_nop,
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
try_find_pchi(const struct dump_trace *traces, size_t i, size_t ntraces,
	      uint32_t *pchi)
{
	union owl_trace trace, from;

	//printf("i=%llu\n", (llu_t) i);

	from = traces[i].trace;
	for (; i < ntraces; i++) {
		trace = traces[i].trace;

		assert(!owl_trace_empty_p(trace));

		/* A PCHI trace will be close to the normal return trace.
		 * Support edge case where a timestamp trace is emitted in
		 * between the traces. */
		if (trace.lsb_timestamp != from.lsb_timestamp &&
		    trace.lsb_timestamp != ((from.lsb_timestamp + 1) & 0x3ffff))
			return;

		if (trace.kind == OWL_TRACE_KIND_PCHI) {
			/* assert(trace.pchi.priv == to_frame); */
			*pchi = trace.pchi.pchi;
			return;
		}
	}
}

/* TODO: Check options. This isn't needed for the default output format. */
static void
try_populate_frame(const struct dump_trace *traces, size_t i, size_t ntraces,
		   struct call_frame *frame, uint32_t *pchi)
{
	union owl_trace trace;
	const struct dump_trace *return_trace;
	int rel_frame = 0;
	bool found = false;

	for (;i < ntraces; i++) {
		trace = traces[i].trace;

		/* HACK: We should be able to get the exact size from the
		   driver.  */
		assert(!owl_trace_empty_p(trace));

		switch (trace.kind) {
		case OWL_TRACE_KIND_EXCEPTION:
		case OWL_TRACE_KIND_UECALL:
		case OWL_TRACE_KIND_SECALL:
			rel_frame++;
			break;
		case OWL_TRACE_KIND_RETURN:
			rel_frame--;
			if (rel_frame == 0) {
				return_trace = &traces[i];
				found = true;
			}
			break;
		}

		if (found)
			break;
	}

	if (found)
		frame->return_trace = return_trace;
	else
		frame->return_trace = NULL;
	assert(found);

	/* H/W writes the PCHI trace after the normal
	 * trace so we need to look forward in the
	 * buffer to find it. */
	try_find_pchi(traces, i, ntraces, pchi);
}

struct options {
	enum { OUTFMT_NORMAL, OUTFMT_FLAME } outfmt;
	bool verbose;
	const char *input;
};

static size_t
count_traces(const uint8_t *tracebuf, size_t tracebuf_size)
{
	union owl_trace trace;
	size_t n = 0, i = 0;

	while (true) {
		memcpy(&trace, &tracebuf[i], min(8, tracebuf_size - i));
		if (i >= tracebuf_size || owl_trace_empty_p(trace))
			break;
		i += owl_trace_size(trace);
		n++;
	}
	return n;
}

static bool
sched_eq_p(const struct owl_metadata_entry *a,
	   const struct owl_metadata_entry *b)
{
	if (a->pid != b->pid)
		return false;
	if (a->ppid != b->ppid)
		return false;
	if (strncmp(a->comm, b->comm, OWL_TASK_COMM_LEN))
		return false;
	return true;
}

static bool
sched_task_eq_p(const struct owl_metadata_entry *a,
		const struct owl_task *b)
{
	if (a->pid != b->pid)
		return false;
	if (a->ppid != b->ppid)
		return false;
	if (strncmp(a->comm, b->comm, OWL_TASK_COMM_LEN))
		return false;
	return true;
}

/* count unique number of tasks in trace
 * TODO: We assume that there is no pid reuse during the time we're sampling */
static size_t
unique_tasks(const struct owl_metadata_entry *metadata, size_t metadata_size)
{
	size_t i, j, n = 0;
	const size_t num_meta_entries = metadata_size / sizeof(*metadata);
	bool *counted, done = false;

	/* Track already counted entires */
	counted = calloc(num_meta_entries, sizeof(*metadata));

	/* Simple O^2 search */
	for (i = 0; i < num_meta_entries && !done; i++) {
		if (counted[i])
			continue;

		done = true;

		/* mark the duplicates */
		for (j = i + 1; j < num_meta_entries; j++) {
			if (counted[j])
				continue;

			if (sched_eq_p(&metadata[i], &metadata[j]))
				counted[j] = true;
			else
				done = false; /* at least one more unique */
		}
		n++;
	}

	free(counted);
	return n;
}

static void
copy_task(struct owl_task *task, const struct owl_metadata_entry *metadata)
{
	/* TODO: *task = metadata->task; */
	task->cpu	= metadata->cpu;
	task->has_mm	= metadata->has_mm;
	task->in_execve	= metadata->in_execve;
	task->kthread	= metadata->kthread;
	task->pid	= metadata->pid;
	task->ppid	= metadata->ppid;
	memcpy(&task->comm, &metadata->comm, OWL_TASK_COMM_LEN);
}

static void
create_tasks(struct owl_task *tasks, size_t ntasks,
	     const struct owl_metadata_entry *metadata, size_t metadata_size)
{
	size_t i, j, n = 0;
	const size_t num_meta_entries = metadata_size / sizeof(*metadata);
	bool *counted, done = false;

	/* Track already counted entires */
	counted = calloc(num_meta_entries, sizeof(*metadata));

	/* Simple O^2 search */
	for (i = 0; i < num_meta_entries && !done; i++) {
		if (counted[i])
			continue;

		copy_task(&tasks[n], &metadata[i]);

		counted[i] = true;
		done = true;

		/* mark the duplicates */
		for (j = i + 1; j < num_meta_entries; j++) {
			if (counted[j])
				continue;

			if (sched_eq_p(&metadata[i], &metadata[j]))
				counted[j] = true;
			else
				done = false; /* at least one more unique */
		}

		n++;
	}
	free(counted);

	assert(n == ntasks);
}

/* Timestamp and tie each trace to a task */
static void
preprocess_traces(struct dump_trace *out, const uint8_t *tracebuf,
		  size_t tracebuf_size, size_t n,
		  const struct owl_metadata_entry *metadata,
		  size_t metadata_size)
{
	size_t i, offs = 0;
	union owl_trace trace, prev_timestamp = { 0 };
	uint64_t absclocks = 0, msbclocks = 0, prev_absclocks = 0;
	uint64_t next_sched = 0ULL;
	unsigned prev_lsb_timestamp = 0;
	const size_t num_meta_entries = metadata_size / sizeof(*metadata);
	const struct owl_metadata_entry *sched_info = &metadata[0];
	const struct owl_metadata_entry
		*last_metadata = &metadata[num_meta_entries - 1];
	bool task_switch;

	for (i = 0; i < n; i++, offs += owl_trace_size(trace)) {
		memcpy(&trace, &tracebuf[offs], min(8, tracebuf_size - offs));
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

		task_switch = absclocks > next_sched;
		if (task_switch) {
			if (sched_info < last_metadata) {
				sched_info++;
				if (sched_info == last_metadata) {
					/* Assume last task lives until
					 * trace stops */
					next_sched = ~0ULL;
				} else {
					next_sched = sched_info->timestamp;
				}
			}
		}

		out[i].trace = trace;
		out[i].timestamp = absclocks;
		out[i].sched_info = sched_info;
#if 0
		out[i].task_switch = task_switch;
#endif
	}
}

/* Initialize with sane values */
const struct dump_trace default_enter0 = {
	.timestamp = ~0, .trace.kind = 7
};
const struct dump_trace default_enter1 = {
	.timestamp = ~0, .trace.kind = 7
};
const struct dump_trace default_enter2 = {
	.timestamp = ~0,
	.trace.kind = 7
};
const struct dump_trace default_ret0 = {
	.timestamp = ~0,
	.trace.ret = { .kind = OWL_TRACE_KIND_RETURN, .pc = ~0 }
};
const struct dump_trace default_ret1 = {
	.timestamp = ~0,
	.trace.ret = { .kind = OWL_TRACE_KIND_RETURN, .pc = ~0 }
};
const struct dump_trace default_ret2 = {
	.timestamp = ~0,
	.trace.ret = { .kind = OWL_TRACE_KIND_RETURN, .pc = ~0 }
};

static void
init_callstacks(struct callstack *callstacks, struct owl_task *tasks,
		size_t ntasks)
{
	size_t i;

	for (i = 0; i < ntasks; i++) {
		callstacks[i].frames[0].enter_trace  = &default_enter0;
		callstacks[i].frames[1].enter_trace  = &default_enter1;
		callstacks[i].frames[2].enter_trace  = &default_enter2;
		callstacks[i].frames[0].return_trace = &default_ret0;
		callstacks[i].frames[1].return_trace = &default_ret1;
		callstacks[i].frames[2].return_trace = &default_ret2;
		callstacks[i].task = &tasks[i];
	}
}

static struct callstack *
find_callstack(const struct owl_metadata_entry *sched_info,
	       struct callstack *callstacks, size_t ntasks)
{
	size_t i;
	struct callstack *callstack;
	for (i = 0; i < ntasks; i++) {
		if (sched_task_eq_p(sched_info, callstacks[i].task)) {
			callstack = &callstacks[i];
			break;
		}
	}

	assert(callstack != NULL);
	return callstack;
}

void dump_trace(const uint8_t *tracebuf, size_t tracebuf_size,
		const struct owl_metadata_entry *metadata, size_t metadata_size,
		struct owl_map_info *maps, size_t map_info_size,
		struct options *options)
{
	/* TODO: Add support for nested interrupts */

	size_t i = 0;
	const size_t num_map_entries = map_info_size / sizeof(*maps);
	int to_frame, from_frame = 0; /* See comment about callstack/frame levels */
	/* struct call_frame call_frame[3] = { 0 }; */
	printfn_t *printfn;
	const struct owl_metadata_entry *prev_sched;
	size_t ntraces, ntasks;
	struct dump_trace *traces;
	struct owl_task *tasks;
	struct callstack *callstacks, *current_callstack;
	uint32_t pchi[3] = { 0 };

	if (options->outfmt == OUTFMT_FLAME)
		printfn = print_flame_trace;
	else if (options->verbose)
		printfn = default_verbose_print_trace;
	else
		printfn = default_print_trace;

	/* Count number of traces */
	ntraces = count_traces(tracebuf, tracebuf_size);
	/* Count number of unique tasks */
	ntasks = unique_tasks(metadata, metadata_size);
	if (!ntraces || !ntasks)
		return;
	traces = calloc(ntraces, sizeof(*traces));
	tasks = calloc(ntasks, sizeof(*tasks));
	callstacks = calloc(ntasks, sizeof(*callstacks));
	assert(tasks != NULL && traces != NULL && callstacks != NULL);

	preprocess_traces(traces, tracebuf, tracebuf_size, ntraces,
			  metadata, metadata_size);
	prev_sched = traces[0].sched_info;

	create_tasks(tasks, ntasks, metadata, metadata_size);

	init_callstacks(callstacks, tasks, ntasks);

	/* Sort the map info so we can binary search it */
	sort_maps(maps, num_map_entries);

	/* Callstack/frame levels:
	 * 0: ecall <--> 1: mcall <--> 2: (interrupt or exception) */

	/* The first trace should be a timestamp. */
	ERROR_ON(traces[0].trace.kind != OWL_TRACE_KIND_TIMESTAMP,
		 "%s", "First trace is not a timestamp!\n");
	to_frame = 0;
	/* Walk trace buffer to determine initial recursion level. */
	for (i = 0; i < ntraces; i++) {
		assert(!owl_trace_empty_p(traces[i].trace));

		switch (traces[i].trace.kind) {
		case OWL_TRACE_KIND_SECALL:
		case OWL_TRACE_KIND_EXCEPTION:
			to_frame++;
			break;
		case OWL_TRACE_KIND_UECALL:
			to_frame++;
			break;
		case OWL_TRACE_KIND_RETURN:
			to_frame--;
		default: continue;
		}
		break;
	}
	from_frame = to_frame;
	printf("from=%d\n", from_frame);

	prev_sched = &metadata[0];
	current_callstack = find_callstack(prev_sched, callstacks, ntasks);
	/* Print first scheduled task */
	if (options->outfmt != OUTFMT_FLAME || 1)
		print_metadata(prev_sched,
			       traces[0].trace.timestamp.timestamp, '\n');

	for (i = 0; i < ntraces; i++) {

		assert(!owl_trace_empty_p(traces[i].trace));

		bool task_switch = prev_sched != traces[i].sched_info;
		if (task_switch) {
			current_callstack =
				find_callstack(traces[i].sched_info, callstacks,
					       ntasks);
#if 0
			current_callstack->frames[0].task_switch = true;
			current_callstack->frames[1].task_switch = true;
			current_callstack->frames[2].task_switch = true;
#endif
			assert(traces[i].sched_info != NULL);
			if (options->outfmt != OUTFMT_FLAME || 1) {
				print_metadata(traces[i].sched_info,
					       prev_sched->timestamp,
					       '\n');
			}
		}
		prev_sched = traces[i].sched_info;

		from_frame = to_frame;
		if (traces[i].trace.kind != OWL_TRACE_KIND_TIMESTAMP &&
		    traces[i].trace.kind != OWL_TRACE_KIND_PCHI) {
			/* The seemingly duplicate statements for setting up
			 * the call_frame in both if cases below are needed.
			 * Since a trace usually starts with a return trace
			 * from the tracectrl driver (level=1) and back to the
			 * user space process 'owl' (level=0), there won't be a
			 * matching ecall trace for the first return trace. */
			if (traces[i].trace.kind == OWL_TRACE_KIND_RETURN) {
				to_frame--;
				/* H/W writes the PCHI trace after the normal
				 * trace so we need to look forward in the
				 * buffer to find it. */
				try_find_pchi(traces, i, ntraces,
					      &pchi[to_frame]);
				current_callstack->frames[to_frame].return_trace = &traces[i];
			} else {
				/* Flame output need the complete frame info */
				try_populate_frame(traces, i, ntraces,
						   &current_callstack->frames[from_frame], &pchi[from_frame]);
				to_frame++;
				current_callstack->frames[to_frame].enter_trace = &traces[i];
			}
		}
		assert(0 <= to_frame && to_frame < 3);
		assert(0 <= from_frame && from_frame < 3);

		/* TODO: Global state should go in separate struct instead of
		 * copying it here */
		current_callstack->frameno = to_frame;
		current_callstack->frames[0].pchi = pchi[0];
		current_callstack->frames[1].pchi = pchi[1];
		current_callstack->frames[2].pchi = pchi[2];

		{
			struct print_args args = {
				.trace			= traces[i].trace,
				.timestamp		= traces[i].timestamp,
				.maps			= maps,
				.num_map_entries	= num_map_entries,
				.sched_info		= traces[i].sched_info,
				.pc_bits		= 39,
				.sign_extend_pc		= true,
				.delim			= '\n'
			};
			printfn[traces[i].trace.kind](&args, current_callstack);
		}

		if (traces[i].trace.kind == OWL_TRACE_KIND_RETURN)
			current_callstack->frames[from_frame].enter_trace = NULL;
	}

	free(traces);
	free(tasks);
	free(callstacks);
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
