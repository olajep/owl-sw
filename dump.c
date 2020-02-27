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

static void *source_info_hashmap;

/* A preprocessed trace with context */
struct dump_trace {
	uint64_t			timestamp;
	union owl_trace			trace;
	const struct owl_sched_info_full *sched_info;
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
};

struct map_search_key {
	int pid;
	uint64_t pc;
};

typedef long long unsigned int llu_t;
typedef void (* const printfn_t)(struct print_args *, struct callstack *);
typedef void (* const print_schedfn_t)
	(const struct owl_sched_info_full *, uint64_t, uint64_t, int, char);
typedef void (* const print_prologuefn_t)
	(const struct owl_trace_file_header *file_header);
typedef void (* const print_epiloguefn_t)
	(const struct owl_trace_file_header *file_header);

struct printer {
	printfn_t		*print_trace;
	print_schedfn_t		print_sched;
	print_prologuefn_t	print_prologue;
	print_epiloguefn_t	print_epilogue;
};

/* Bytes */
static size_t
owl_trace_size(union owl_trace trace)
{
	return (trace.kind & 1) ? 8 : 4;
}

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

static struct owl_map_info *find_map(const struct map_search_key *key,
				     const struct owl_map_info *maps,
				     size_t num_map_entries);

static uint32_t
sign_extend_pchi(uint32_t pchi, unsigned pc_bits)
{
	unsigned sign_bits = pc_bits - 32;
	pchi &= ((1 << sign_bits) - 1);
	if (pchi & (1ULL << (sign_bits - 1)))
		pchi = (~0ULL ^ ((1 << sign_bits) - 1)) | pchi;

	return pchi;
}

static uint64_t
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

static const char *
return_type(struct call_frame *frame)
{
	if (frame->enter_trace == NULL || frame->enter_trace->trace.kind == 7) {
		/* Return from other task */
		return "scdret";
	}

	switch (frame->enter_trace->trace.kind) {
	case OWL_TRACE_KIND_UECALL: return "eret";
	case OWL_TRACE_KIND_SECALL: return "mret";
	case OWL_TRACE_KIND_EXCEPTION:
		if (frame->enter_trace->trace.exception.cause & 128)
			return "iret";
		else
			return "exret";
	default:
		printf("enter trace kind=%d\n", frame->enter_trace->trace.kind);
		assert("wrong return trace" && 0);
		return "?????";
	}
}

static const char *
binary_name(struct print_args *a, struct callstack *c, uint64_t *pc,
	    uint64_t *offset)
{
	const struct owl_sched_info_full *sched =
		this_frame(c)->return_trace->sched_info;
	*pc = full_pc(this_frame(c), a->pc_bits, a->sign_extend_pc);
	*offset = *pc;

	if (frame_down(c)->enter_trace != NULL &&
	    frame_down(c)->enter_trace->sched_info) {
		assert(frame_down(c)->enter_trace->sched_info->base.pid ==
		       this_frame(c)->return_trace->sched_info->base.pid);
	}

	const char *binary = "'none'";
	if (this_frameno(c) == 1) {
		binary = "/boot/vmlinux";
	} else if (this_frameno(c) == 0) {
		struct owl_map_info *map;
		struct map_search_key key = {
			.pid = sched->base.pid,
			.pc = *pc
		};

		/* Detecting when we should use the parent's memory mapping
		 * seems fragile. We might have to add timestamping to the
		 * mmaping sched_info to detect whether the region is alive at
		 * this point in time. */
		map = find_map(&key, a->maps, a->num_map_entries);
		if (!map && sched->base.in_execve) {
			key.pid = sched->base.ppid;
			map = find_map(&key, a->maps, a->num_map_entries);
		}

		if (map) {
			binary = map->path;
			*offset = *pc - map->vm_start;
		} else {
			binary = "'none'";
		}
	}
	assert(this_frameno(c) < 2);

	return binary;
}

static void
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

static void
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
		*desc = "ecall";
		*cause = frame->enter_trace->trace.ecall.regval;
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
		*cause = frame->enter_trace->trace.ecall.regval;
		if (*cause >= ARRAY_SIZE(mcalltable)) {
			*name = NULL;
		} else {
			*name = mcalltable[*cause];
		}
		*cause = frame->enter_trace->trace.ecall.regval;
		break;
	case OWL_TRACE_KIND_EXCEPTION:
		describe_exception_frame(frame, type, name, desc, cause);
		break;
	default:
		assert(0 && "Wrong trace kind\n");
	}
}

static llu_t
rel_timestamp(struct print_args *a, const struct dump_trace *trace)
{
	return trace->timestamp - a->start_time;
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
	const char *type, *name;
	unsigned function;

	describe_frame_enter(this_frame(c), &type, &name, NULL, &function);
	/* TODO: Support hcall if we add support for it in H/W */
	printf("@=[%020llu] cpu=%03d %s\t\tfunction=[%05d] name=[%s]%c",
	       rel_timestamp(a, this_frame(c)->enter_trace), a->cpu, type, function, name, a->delim);
}

/* TODO: popen() is SLOW!!!. Should use a hashtable. */
static bool
source_info(struct print_args *a, struct callstack *c,
	    char *buf, size_t bufsize, const char *binary, llu_t poffs)
{
	llu_t vaddr;
	FILE *stream;
	char cmdline[2048], tmp[64], *p;
	char path[1024];
	size_t pos = 0;
	struct stat statbuf;
	int ret;

	if (source_hash_find(source_info_hashmap, binary, poffs, buf, bufsize))
		return true;

	/* Path */
	pos = 0;
	strncpy(&path[pos], a->sysroot, sizeof(path) - pos - 1);
	pos += strnlen(a->sysroot, 1024);
	if (pos >= sizeof(path))
		return false;
	strncpy(&path[pos], binary, sizeof(path) - pos);
	pos += strnlen(binary, 1024);
	if (pos >= sizeof(cmdline))
		return false;
	path[pos] = '\0';

	if (stat(path, &statbuf) != 0)
		return false;

	if (strncmp(binary, "'none'", sizeof("'none'")) == 0)
		return false;

	if (this_frameno(c) > 0) {
		vaddr = poffs;
		goto have_vaddr;
	}

	/* offs2vaddr */
	pos = 0;
	strncpy(&cmdline[pos], "./offs2vaddr ", sizeof(cmdline) - pos);
	pos += strlen("./offs2vaddr ");
	strncpy(&cmdline[pos], path, sizeof(cmdline) - pos);
	pos += strnlen(path, 1024);
	if (pos >= sizeof(cmdline))
		return false;
	if (pos >= sizeof(cmdline) + 25)
		return false;
	if ((ret = snprintf(&cmdline[pos], 25, " 0x%llx", poffs)) <= 0)
		return false;
	pos += ret;
	if (pos >= sizeof(cmdline))
		return false;
	cmdline[pos] = '\0';

	stream = popen(cmdline, "r");
	if (!stream)
		return false;
	if (fscanf(stream, "%32s", tmp) != 1) {
		pclose(stream);
		return false;
	}
	pclose(stream);
	vaddr = strtoull(tmp, NULL, 0);

have_vaddr:
	/* addr2line */
	pos = 0;
	strncpy(&cmdline[pos], "addr2line -e ", sizeof(cmdline) - pos);
	pos += strlen("addr2line -e ");
	strncpy(&cmdline[pos], path, sizeof(cmdline) - pos);
	pos += strnlen(path, 1024);
	if (pos >= sizeof(cmdline))
		return false;
	ret = snprintf(&cmdline[pos], sizeof(cmdline) - pos, " 0x%llx ", vaddr);
	if (ret <= 0)
		return false;
	pos += ret;
	if (pos >= sizeof(cmdline))
		return false;
	strncpy(&cmdline[pos], "-f -s", sizeof(cmdline) - pos);
	pos += sizeof("-f -p");
	if (pos >= sizeof(cmdline))
		return false;
	cmdline[pos] = '\0';

	stream = popen(cmdline, "r");
	if (!stream)
		return false;
	if ((ret = fread(buf, 1, bufsize - 1, stream)) <= 0) {
		pclose(stream);
		return false;
	}
	pclose(stream);
	buf[ret - 1] = '\0';
	p = strstr(buf, "\n");
	if (p) {
		*p = ':';
		p = strstr(p, " (");
		if (p)
			*p = '\0';
	}

	// Cache the result
	source_hash_insert(source_info_hashmap, binary, poffs, buf);

	return true;
}

static void
print_return_trace(struct print_args *a, struct callstack *c)
{
	char buf[2048];
	bool have_source_info;

	/* TODO: Support hcall if we add support for it in H/W */
	/* TODO: Print time delta */
	const char *type;
	uint64_t pc, offset;
	const char *binary = "'none'";

	pc = full_pc(this_frame(c), a->pc_bits, a->sign_extend_pc);
	offset = pc;

	if (frame_down(c)->enter_trace == NULL ||
	    frame_down(c)->enter_trace->trace.kind == 7 ) {
		/* Return from other task */
		type = "scdret";
	} else
	type = return_type(frame_down(c));
	binary = binary_name(a, c, &pc, &offset);

	have_source_info = source_info(a, c, buf, sizeof(buf), binary, offset);
	printf("@=[%020llu] cpu=%03d %-5s\t\tpc=[%016llx] retval=[%05d] file=[%s+0x%llx] source=[%s]%c",
	       rel_timestamp(a, this_frame(c)->return_trace), a->cpu, type,
	       (llu_t) pc, this_frame(c)->return_trace->trace.ret.regval, binary,
	       (llu_t) offset, have_source_info ? buf : "'none'", a->delim);
}

static void
print_exception_trace(struct print_args *a, struct callstack *c)
{
	const char *type, *name, *desc;
	unsigned cause;

	describe_frame_enter(this_frame(c), &type, &name, &desc, &cause);
	printf("@=[%020llu] cpu=%03d %s\t%s=[0x%03x] name=%s%c",
	       rel_timestamp(a, this_frame(c)->enter_trace), a->cpu, type, desc, cause, name,
	       a->delim);
}

static void
print_timestamp_trace(struct print_args *a, struct callstack *c)
{
	(void)c;
	printf("@=[%020llu] cpu=%03d timestamp\tt=[%020llu]%c",
	       rel_timestamp(a, a->trace), a->cpu,
	       (llu_t) a->trace->trace.timestamp.timestamp,
	       a->delim);
}

static void
print_invalid_trace(struct print_args *a, struct callstack *c)
{
	(void)c;
	long long data;
	unsigned kind = a->trace->trace.kind;
	memcpy(&data, &a->trace, sizeof(data));
	printf("INVALID TRACE kind=%u data=[%016llx]%c", kind, data, a->delim);
}

static void
print_pchi_trace(struct print_args *a, struct callstack *c)
{
	(void)c;
	uint32_t pchi = a->trace->trace.pchi.pchi;
	if (a->sign_extend_pc)
		pchi = sign_extend_pchi(pchi, a->pc_bits);
	printf("@=[%020llu] cpu=%03d pchi=[0x%08x] priv=[%d]%c",
	       rel_timestamp(a, a->trace), a->cpu, pchi,
	       a->trace->trace.pchi.priv, a->delim);
}

static void
filtered_print_sched_info(const struct owl_sched_info_full *entry,
			  uint64_t timestamp, uint64_t until,
			  int cpu, char delim)
{
	assert(entry->comm[OWL_TASK_COMM_LEN - 1] == '\0');

	if (entry->base.cpu != cpu)
		return;

	printf("@=[%020llu] cpu=%03d sched\t\tcomm=[%s] pid=[%05d] until=[%020llu] cpu=[%d]%c",
	       (llu_t) timestamp, (int) entry->base.cpu,
	       entry->comm, entry->base.pid,
	       (llu_t) until, (int) entry->base.cpu, delim);
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

static struct printer default_printer = {
	.print_trace = default_print_trace,
	.print_sched = filtered_print_sched_info
};

static struct printer default_verbose_printer = {
	.print_trace = default_verbose_print_trace,
	.print_sched = filtered_print_sched_info
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
		printf("%llu\n", rel_timestamp(a, this_frame(c)->enter_trace));
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
		printf("%llu\n", rel_timestamp(a, this_frame(c)->return_trace));
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

	if (c.task->pid == 0) {
		/* Special case the idle task */
		printf("%s;", c.task->comm);
	} else {
		printf("%s/%d;", c.task->comm, c.task->pid);
	}

	c.frameno = 0;
	if (orig_a->trace->trace.kind != OWL_TRACE_KIND_RETURN)
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

	a->delim = ';';
	c->frameno--;
	if (this_frame(c)->return_trace != NULL)
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
		if (frame_up(c)->return_trace != NULL) {
			printf("%s=%d%c", name,
			       frame_up(c)->return_trace->trace.ret.regval, a->delim);
		} else {
			printf("%s%c", name, a->delim);
		}
	}
}

static void
print_flame_return_trace(struct print_args *a, struct callstack *c)
{
	/* TODO: Support hcall if we add support for it in H/W */
	uint64_t pc, offset;
	char buf[2048];
	bool have_source_info;
	const char *binary = "'none'";

	pc = full_pc(this_frame(c), a->pc_bits, a->sign_extend_pc);
	offset = pc;
	binary = binary_name(a, c, &pc, &offset);
	have_source_info = source_info(a, c, buf, sizeof(buf), binary, offset);

	if (have_source_info)
		printf("file://%s+0x%llx [%s]%c", binary, (llu_t) offset, buf, a->delim);
	else
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

static void
flame_print_sched_info(const struct owl_sched_info_full *entry,
			 uint64_t timestamp, uint64_t until,
			 int cpu, char delim)
{
	(void)entry;
	(void)timestamp;
	(void)until;
	(void)cpu;
	(void)delim;
}

static struct printer flame_printer = {
	.print_trace = print_flame_trace,
	.print_sched = flame_print_sched_info
};

/* End FlameChart friendly output format */

/* Begin KUTrace JSON format */

static void
kutrace_print_ecall_trace(struct print_args *a, struct callstack *c)
{
	unsigned function;
	float ts_enter, ts_return;
	bool exit_p;
	const char *enter_type = NULL, *enter_name = NULL;
	int exit_event = 0x20000;
	const float freq = 100000000.0f;

	describe_frame_enter(this_frame(c), &enter_type, &enter_name, NULL, &function);

	ts_enter = rel_timestamp(a, this_frame(c)->enter_trace) / freq;
	/* TODO: What should this be? Next sched??? */
	ts_return = 0.001f;

	exit_p = this_frame(c)->enter_trace->trace.kind == OWL_TRACE_KIND_UECALL &&
		 (function == tgt_sys_exit || function == tgt_sys_exit_group);
	if (!exit_p)
		return;

	/* Format: time dur cpu pid rpcid event arg retval ipc name */
	printf("[%12.8f, %10.8f, %d, %d, %d, %u, %d, %u, %d, \"%s\"],\n",
	       ts_enter, ts_return, a->cpu, c->task->pid, 0,
	       exit_event, exit_event,
	       function, 0, enter_name);
}

static void
kutrace_print_return_trace(struct print_args *a, struct callstack *c)
{
	char buf[2048];
	bool have_source_info;

	/* TODO: Support hcall if we add support for it in H/W */
	/* TODO: Print time delta */
	const char *type;
	uint64_t pc, offset;
	const char *binary = "'none'";
	/* TODO: Don't make frequency a constant */
	const float freq = 100000000.0f;

	const char *enter_type, *enter_name;
	unsigned enter_function;

	if (frame_down(c)->enter_trace == NULL || frame_down(c)->enter_trace->trace.kind == 7) {
		return;
	}

	describe_frame_enter(frame_down(c), &enter_type, &enter_name, NULL, &enter_function);

	pc = full_pc(this_frame(c), a->pc_bits, a->sign_extend_pc);
	offset = pc;

	if (frame_down(c)->enter_trace == NULL) {
		/* Return from other task */
		type = "scdret";
	} else {
		type = return_type(frame_down(c));
	}
	binary = binary_name(a, c, &pc, &offset);

	have_source_info = source_info(a, c, buf, sizeof(buf), binary, offset);

	switch (frame_down(c)->enter_trace->trace.kind) {
	case OWL_TRACE_KIND_UECALL:
		enter_function |= 0x800;
		break;
	case OWL_TRACE_KIND_SECALL:
		enter_function |= 0x000; /* is_kernel ??? */
		break;
	case OWL_TRACE_KIND_EXCEPTION:
		if (frame_down(c)->enter_trace->trace.exception.cause & 128) {
			enter_function |= 0x500; /* is_irq */
			enter_function &= ~128;
		} else {
			enter_function |= 0x400; /* is_fault */
		}
		break;
	default:
		break;
	}

	float ts_enter =   rel_timestamp(a, frame_down(c)->enter_trace)  / freq;
	float ts_return =  rel_timestamp(a, this_frame(c)->return_trace) / freq;
	/* Format: time dur cpu pid rpcid event arg retval ipc name */
	printf("[%12.8f, %10.8f, %d, %d, %d, %u, %d, %d, %d, \"%s\"],\n",
	       ts_enter, ts_return - ts_enter, a->cpu, c->task->pid, 0,
	       enter_function, enter_function,
	       this_frame(c)->return_trace->trace.ret.regval, 0, enter_name);
}

static void
kutrace_print_invalid_trace(struct print_args *a, struct callstack *c)
{
	(void)c;
	long long data;
	unsigned kind = a->trace->trace.kind;
	memcpy(&data, &a->trace, sizeof(data));
	printf("INVALID TRACE kind=%u data=[%016llx]%c", kind, data, a->delim);
}

static void
kutrace_print_sched_info(const struct owl_sched_info_full *entry,
			 uint64_t timestamp, uint64_t until,
			 int cpu, char delim)
{
	(void)delim;

	int event;
	assert(entry->comm[OWL_TASK_COMM_LEN - 1] == '\0');

	if (entry->base.cpu != cpu)
		return;

	const float freq = 100000000.0f;
	float ts_enter =   ((float) timestamp) / freq;
	float ts_return =  ((float) until) / freq;

	event = 0x10000 | entry->base.pid;

	/* Format: time dur cpu pid rpcid event arg retval ipc name */
	printf("[%12.8f, %10.8f, %d, %d, %d, %u, %d, %d, %d, \"%s/%d\"],\n",
	       ts_enter, ts_return - ts_enter, cpu, entry->base.pid, 0,
	       event, 0, 0, 0, entry->comm, entry->base.pid);
}

static void
kutrace_print_prologue(const struct owl_trace_file_header *file_header)
{
	time_t start_seconds, stop_seconds;
	struct tm *start_tm, *stop_tm;
	char start_str[128] = { 0 }, stop_str[128] = { 0 };

	start_seconds = file_header->start_time / 1000000000L;
	start_tm = gmtime(&start_seconds);
	strftime(start_str, sizeof(start_str), "%Y-%m-%d_%H:%M:%S", start_tm);

	stop_seconds = file_header->stop_time / 1000000000L;
	stop_tm = gmtime(&stop_seconds);
	strftime(stop_str, sizeof(stop_str), "%Y-%m-%d_%H:%M:%S", stop_tm);

	printf(\
"{\n"
"\"axisLabelX\" : \"Time (sec)\",\n"
"\"axisLabelY\" : \"CPU Number\",\n"
"\"Comment\" : \"CSTrace KUTrace compatible JSON V0\",\n"
"\"flags\" : 0,\n"
"\"shortMulX\" : 1,\n"
"\"shortUnitsX\" : \"s\",\n"
"\"thousandsX\" : 1000,\n"
"\"title\" : \"Host: %s\",\n"
"\"tracebase\" : \"%s\",\n"
"\"traceend\" : \"%s\",\n"
"\"version\" : 0,\n"
"\"events\" : [\n",
	file_header->hostname, start_str, stop_str);
}

static void
kutrace_print_epilogue(const struct owl_trace_file_header *file_header)
{
	printf("\
[999.0, 0.0, 0, 0, 0, 0, 0, 0, 0, \"\"]\n\
]}\n");
}

static printfn_t print_kutrace_trace[8] = {
	[OWL_TRACE_KIND_UECALL]		= kutrace_print_ecall_trace,
	[OWL_TRACE_KIND_RETURN]		= kutrace_print_return_trace,
	[OWL_TRACE_KIND_SECALL]		= print_nop,
	[OWL_TRACE_KIND_TIMESTAMP]	= print_nop,
	[OWL_TRACE_KIND_EXCEPTION]	= print_nop,
	[OWL_TRACE_KIND_PCHI]		= print_nop,
	[6]				= kutrace_print_invalid_trace,
	[7]				= print_nop,
};

static struct printer kutrace_json_printer = {
	.print_trace	= print_kutrace_trace,
	.print_sched	= kutrace_print_sched_info,
	.print_prologue	= kutrace_print_prologue,
	.print_epilogue	= kutrace_print_epilogue
};

/* End KUTrace JSON format */

static int
find_compare_maps(const void *_key, const void *_elem)
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

static struct owl_map_info *
find_map(const struct map_search_key *key,
	 const struct owl_map_info *maps, size_t num_map_entries)
{
	return bsearch(key, maps, num_map_entries, sizeof(*maps),
		       find_compare_maps);
}

static int
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

static void
sort_maps(struct owl_map_info *maps, size_t num_map_entries)
{
	qsort(maps, num_map_entries, sizeof(*maps), sort_compare_maps);
}

static bool task_eq_p(const struct owl_task *a, const struct owl_task *b);

static bool
try_find_pchi(const struct dump_trace *traces, size_t ntraces, size_t i,
	      uint32_t *pchi)
{
	union owl_trace trace, from;

	from = traces[i].trace;
	for (; i < ntraces; i++) {
		trace = traces[i].trace;

		/* A PCHI trace will be close to the normal return trace.
		 * Support edge case where a timestamp trace is emitted in
		 * between the traces. */
		if (trace.lsb_timestamp != from.lsb_timestamp &&
		    trace.lsb_timestamp != ((from.lsb_timestamp + 1) & 0x3ffff))
			return false;

		if (trace.kind == OWL_TRACE_KIND_PCHI) {
			*pchi = trace.pchi.pchi;
			return true;
		}
	}
	return false;
}

static void
find_pchi_backwards(const struct dump_trace *ret_trace,
			uint32_t *pchi, int frameno,
			struct dump_trace * const *pchi_traces,
			size_t npchitraces)
{
	size_t i;
	uint64_t timestamp = ret_trace->timestamp;
	union owl_trace trace;

	assert(npchitraces);

	i = npchitraces;
	while (i--) {
		trace = pchi_traces[i]->trace;

		/* Skip PCHIs that come *after* the return trace */
		if (pchi_traces[i]->timestamp > timestamp)
			continue;

		/* TODO: Could break with debug bit? */
		if (trace.pchi.priv == frameno) {
			*pchi = trace.pchi.pchi;
			return;
		}
	}
	/* 0 is the initial value in H/W, and will thus never be outputted in
	 * the start of a trace */
	*pchi = 0;
}

static void
find_pchi(const struct dump_trace *traces, size_t ntraces, size_t i,
	  uint32_t *pchi, int frameno,
	  struct dump_trace * const *pchi_traces, size_t npchitraces)
{
	/* H/W writes the PCHI trace after the normal
	 * trace so we need to look forward in the
	 * buffer to find it... */
	if (try_find_pchi(traces, ntraces, i, pchi))
		return;

	/* ... and if we couldn't find it look backwards in the trace buffer to
	 * get the most recent value */
	find_pchi_backwards(&traces[i], pchi, frameno,
			    pchi_traces, npchitraces);
}

static void
populate_frame(const struct dump_trace *traces, size_t ntraces, size_t i,
	       struct call_frame *frame, uint32_t *pchi, int frameno,
	       struct dump_trace * const *pchi_traces, size_t npchitraces)
{
	union owl_trace trace;
	const struct dump_trace *return_trace = NULL;
	const struct owl_sched_info_full *task = traces[i].sched_info;
	int rel_frame = 0;
	bool found = false;

	for (;i < ntraces; i++) {
		trace = traces[i].trace;

		assert(owl_trace_valid_p(trace));

		switch (trace.kind) {
		case OWL_TRACE_KIND_EXCEPTION:
		case OWL_TRACE_KIND_UECALL:
		case OWL_TRACE_KIND_SECALL:
			rel_frame++;
			break;
		case OWL_TRACE_KIND_RETURN:
			rel_frame--;
			if (rel_frame == 0 &&
			    task->base.pid == traces[i].sched_info->base.pid) {
				return_trace = &traces[i];
				found = true;
			}
			break;
		}

		if (found)
			break;
	}

	frame->return_trace = return_trace;
	if (found) {
		find_pchi(traces, ntraces, i, pchi, frameno,
			  pchi_traces, npchitraces);
	}
}

struct options {
	enum { OUTFMT_NORMAL, OUTFMT_FLAME, OUTFMT_KUTRACE_EVENT } outfmt;
	bool verbose;
	const char *input;
	bool have_cpu;
	int cpu;
	const char *sysroot;
};

static void
count_traces(const uint8_t *tracebuf, size_t tracebuf_size,
	     size_t *ntraces, size_t *npchitraces)
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
	*npchitraces = npchi;
}

static bool
sched_task_task_eq_p(const struct owl_sched_info *a, const struct owl_task *b)
{
#if 0
	if (a == b)
		return true;
	if (!a && !b)
		return true;
	if (!a || !b)
		return false;
#endif
	if (a->pid != b->pid)
		return false;
	if (a->ppid != b->ppid)
		return false;
#if 0
	if (strncmp(a->comm, b->comm, OWL_TASK_COMM_LEN))
		return false;
#endif
	return true;
}


static bool
sched_task_eq_p(const struct owl_sched_info *a,
		const struct owl_sched_info *b)
{
#if 0
	if (a == b)
		return true;
	if (!a && !b)
		return true;
	if (!a || !b)
		return false;
#endif
	if (a->pid != b->pid)
		return false;
	if (a->ppid != b->ppid)
		return false;
#if 0
	if (strncmp(a->comm, b->comm, OWL_TASK_COMM_LEN))
		return false;
#endif
	return true;
}

static bool
task_eq_p(const struct owl_task *a,
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
unique_tasks(const struct owl_sched_info_full *sched_info,
	     size_t sched_info_entries)
{
	size_t i, j, n = 0;
	bool *counted, done = false;

	/* Track already counted entires */
	counted = calloc(sched_info_entries, sizeof(*counted));

	/* Simple O^2 search */
	for (i = 0; i < sched_info_entries && !done; i++) {

		if (counted[i])
			continue;

		/* Mark the duplicates */
		done = true;
		for (j = i + 1; j < sched_info_entries; j++) {
			if (counted[j])
				continue;

			if (sched_task_eq_p(&sched_info[i].base,
					    &sched_info[j].base))
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
fill_in_missing_comms(struct owl_sched_info_full *sched_info,
		      size_t sched_info_entries)
{
	size_t i, j;

	for (i = 1; i < sched_info_entries; i++) {
		if (sched_info[i].base.pid == 0) {
			/* Detect the idle == swapper task */
			memcpy(sched_info[i].comm, "idle", sizeof("idle"));
			sched_info[i].base.full_trace = 1;
			continue;
		}

		if (sched_info[i].base.full_trace)
			continue;
		/* Walk backwards until we find the comm in a previous trace */
		for (j = i; j > 0; j--) {
			if (!sched_info[j - 1].base.full_trace ||
			    !sched_task_eq_p(&sched_info[i].base,
				    	     &sched_info[j - 1].base))
				continue;

			memcpy(sched_info[i].comm, sched_info[j - 1].comm,
			       OWL_TASK_COMM_LEN);
			sched_info[i].base.full_trace = 1;
			break;
		}
	}
}

static void
unpack_sched_info(struct owl_sched_info_full *sched_info,
		  const uint8_t *sched_info_buf, size_t sched_info_size,
		  size_t sched_info_entries)
{
	size_t i, offs, entry_size;
	const struct owl_sched_info *entry;

	for (i = 0, offs = 0;
	     i < sched_info_entries && offs < sched_info_size;
	     i++, offs += entry_size) {
		entry = (const struct owl_sched_info *)
				&sched_info_buf[offs];
		entry_size = owl_sched_info_entry_size(entry);

		memcpy(&sched_info[i], &sched_info_buf[offs], entry_size);
	}
	fill_in_missing_comms(sched_info, sched_info_entries);
}

static void
create_tasks(struct owl_task *tasks, size_t ntasks,
	     const struct owl_sched_info_full *sched_info, size_t sched_info_entries)
{
	size_t i, j, n = 0;
	bool *counted, done = false;

	/* Track already counted entires */
	counted = calloc(sched_info_entries, sizeof(*sched_info));

	/* Simple O^2 search */
	for (i = 0; i < sched_info_entries && !done; i++) {
		bool have_comm = false;

		if (counted[i])
			continue;
		have_comm = sched_info[i].base.full_trace;

		tasks[n].pid = sched_info[i].base.pid;
		tasks[n].ppid = sched_info[i].base.ppid;

		if (sched_info[i].base.full_trace) {
			memcpy(tasks[n].comm, sched_info[i].comm,
			       OWL_TASK_COMM_LEN);
			have_comm = true;
		}

		counted[i] = true;
		done = true;

		/* mark the duplicates */
		for (j = i + 1; j < sched_info_entries; j++) {
			if (counted[j])
				continue;

			if (sched_task_eq_p(&sched_info[i].base,
					    &sched_info[j].base)) {
				counted[j] = true;
				if (have_comm)
					continue;

				if (sched_info[j].base.full_trace) {
					memcpy(tasks[n].comm,
					       sched_info[j].comm,
					       OWL_TASK_COMM_LEN);
					have_comm = true;
				}
			}
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
		  const struct owl_sched_info_full *sched_info,
		  size_t sched_info_entries,
		  struct dump_trace **pchi_traces,
		  int cpu)
{
	size_t i, offs = 0;
	union owl_trace trace, prev_timestamp = { 0 };
	uint64_t absclocks = 0, msbclocks = 0, prev_absclocks = 0;
	uint64_t next_sched = 0ULL;
	unsigned prev_lsb_timestamp = 0;
	const struct owl_sched_info_full *curr_sched = &sched_info[0];
	const struct owl_sched_info_full
		*last_sched = &sched_info[sched_info_entries - 1];

	/* Scheduling info is in one conescutive stream so we need to
	 * filter out the events that belong to this cpu */
	while (curr_sched->base.cpu != cpu && curr_sched != last_sched)
		curr_sched++;

	next_sched = curr_sched->base.timestamp;
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

		while (absclocks > next_sched && curr_sched < last_sched) {
			const struct owl_sched_info_full *tmp = curr_sched;
			do {
				tmp++;
			} while (tmp->base.cpu != cpu && tmp != last_sched);
			if (tmp == last_sched) {
				/* Assume last task lives until
				 * trace stops */
				next_sched = ~0ULL;
			} else {
				curr_sched = tmp;
				next_sched = curr_sched->base.timestamp;
			}
		}

		out[i].trace = trace;
		out[i].timestamp = absclocks;
		out[i].sched_info = curr_sched;
		if (trace.kind == OWL_TRACE_KIND_PCHI)
			*pchi_traces++ = &out[i];
	}
}

/* Initialize with dummy stack traces */
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

static void
init_callstacks(struct callstack *callstacks, struct owl_task *tasks,
		size_t ntasks)
{
	size_t i;

	for (i = 0; i < ntasks; i++) {
		callstacks[i].frames[0].enter_trace  = &default_enter0;
		callstacks[i].frames[1].enter_trace  = &default_enter1;
		callstacks[i].frames[2].enter_trace  = &default_enter2;
		callstacks[i].frames[0].return_trace = NULL;
		callstacks[i].frames[1].return_trace = NULL;
		callstacks[i].frames[2].return_trace = NULL;
		callstacks[i].task = &tasks[i];
	}
}

static struct callstack *
find_callstack(const struct owl_sched_info_full *sched_info,
	       struct callstack *callstacks, size_t ntasks)
{
	size_t i;
	struct callstack *callstack = NULL;
	for (i = 0; i < ntasks; i++) {
		if (sched_task_task_eq_p(&sched_info->base,  callstacks[i].task)) {
			callstack = &callstacks[i];
			break;
		}
	}

	assert(callstack != NULL);
	return callstack;
}

static int
__compute_initial_frame_level(struct dump_trace *traces, size_t ntraces)
{
	int initial = -1;
	unsigned kind;
	size_t i;

	if (!ntraces)
		return 0;

	/* First find a UECALL or SECALL to get a reference point. */
	for (i = 0; i < ntraces; i++) {
		kind = traces[i].trace.kind;
		switch (kind) {
		case OWL_TRACE_KIND_SECALL:
			initial = 1;
			break;
		case OWL_TRACE_KIND_UECALL:
			initial = 0;
			break;
		default:
			continue;
		}
		break;
	}
	if (initial == -1)
		return -1;

	/* Second part. Trace backwards and count returns. */
	for (; i <= 0; i--) {
		kind = traces[i].trace.kind;
		switch (kind) {
		case OWL_TRACE_KIND_RETURN:
			initial++;
			break;
		case OWL_TRACE_KIND_EXCEPTION:
			initial--;
			break;
		}
	}
	if (0 <= initial && initial <= 3)
		return initial;
	else
		return -1;
}

static int
compute_initial_frame_level(struct dump_trace *traces, size_t *ntraces)
{
	int start_frame = 0;
	size_t m, l, r;

	/* Binary search for valid sequence */
	l = 0;
	r = *ntraces;
	while (l != r) {
		m = (l + r + 1) / 2;
		start_frame = __compute_initial_frame_level(traces, m);
		if (start_frame < 0)
			r = m - 1;
		else
			l = m;
	}
	while (m && start_frame < 0) {
		m--;
		start_frame = __compute_initial_frame_level(traces, m);
	}

	if (m == 0)
		start_frame = 0;
	if (m != *ntraces) {
		fprintf(stdwarn,
			"%s: WARNING: Trace broken after %lu traces. Total traces: %lu\n",
			__func__, m, *ntraces);
	}
	*ntraces = m;

	assert(start_frame >= 0);
	return start_frame;
}

static void
dump_trace_one_cpu(const uint8_t *trace_stream, size_t trace_stream_size,
		   const struct owl_sched_info_full *sched_info,
		   size_t sched_info_entries,
		   struct callstack *callstacks, const size_t ntasks,
		   struct owl_map_info *maps, size_t map_info_size,
		   const char *sysroot, struct printer *printer, const int cpu)
{

	size_t i = 0;
	const size_t num_map_entries = map_info_size / sizeof(*maps);
	int to_frame = 0, from_frame; /* See comment about callstack/frame levels */
	const struct owl_sched_info_full *prev_sched, *end_sched;
	size_t ntraces, npchitraces;
	struct dump_trace *traces, **pchi_traces;
	struct callstack *curr_callstack;
	uint32_t pchi[3] = { 0 };

	end_sched = &sched_info[sched_info_entries];

	/* Count number of traces */
	count_traces(trace_stream, trace_stream_size, &ntraces, &npchitraces);
	if (!ntraces)
		return;

	traces = calloc(ntraces, sizeof(*traces));
	pchi_traces = calloc(npchitraces, sizeof(*pchi_traces));

	assert(traces != NULL && pchi_traces != NULL);

	preprocess_traces(traces, trace_stream, trace_stream_size, ntraces,
			  sched_info, sched_info_entries, pchi_traces, cpu);

	/* Callstack/frame levels:
	 * 0: ecall <--> 1: mcall <--> 2: (interrupt or exception) */

	/* The first trace should be a timestamp. */
	ERROR_ON(traces[0].trace.kind != OWL_TRACE_KIND_TIMESTAMP,
		 "%s", "First trace is not a timestamp!\n");

	to_frame = compute_initial_frame_level(traces, &ntraces);

	prev_sched = traces[0].sched_info;
	curr_callstack = find_callstack(prev_sched, callstacks, ntasks);

	/* Print first scheduled task */
	printer->print_sched(traces[0].sched_info, 0,
			     traces[0].sched_info->base.timestamp - traces[0].timestamp,
			     cpu, '\n');

	for (i = 0; i < ntraces; i++) {
		bool task_switch = i && (prev_sched != traces[i].sched_info);

		if (task_switch) {
			curr_callstack =
				find_callstack(traces[i].sched_info, callstacks,
					       ntasks);
			assert(traces[i].sched_info != NULL);
			/*
			* Print scheduled tasks that didn't generate
			* traces.
			* TODO: This should be done for FLAME too.
			*/
			while (prev_sched != traces[i - 1].sched_info) {
				const struct owl_sched_info_full *next_sched;
				next_sched = prev_sched;
				while (++next_sched < end_sched) {
					if (next_sched->base.cpu == cpu)
						break;
			}
			printer->print_sched(
				prev_sched,
				prev_sched->base.timestamp - traces[0].timestamp,
				next_sched->base.timestamp - traces[0].timestamp,
				cpu, '\n');
				prev_sched++;
			}
			printer->print_sched(traces[i].sched_info,
					prev_sched->base.timestamp - traces[0].timestamp,
					traces[i].sched_info->base.timestamp - traces[0].timestamp,
					cpu, '\n');
		}
		prev_sched = traces[i].sched_info;

		from_frame = to_frame;
		/* The seemingly duplicate statements for setting up
		 * the call_frame in both if cases below are needed.
		 * Since a trace usually starts with a return trace
		 * from the tracectrl driver (level=1) and back to the
		 * user space process 'owl' (level=0), there won't be a
		 * matching ecall trace for the first return trace. */
		if (traces[i].trace.kind == OWL_TRACE_KIND_RETURN) {
			to_frame--;
			if (to_frame < 0) {
				fprintf(stdwarn, "WARNING: trace %lu to_frame=%d, adjusting\n", i, to_frame);
				to_frame = 0;
			}
			/* H/W writes the PCHI trace after the normal
			 * trace so we need to look forward in the
			 * buffer to find it. */
			find_pchi(traces, ntraces, i, &pchi[to_frame], to_frame,
				  pchi_traces, npchitraces);
			curr_callstack->frames[to_frame].pchi = pchi[to_frame];
			curr_callstack->frames[to_frame].return_trace = &traces[i];
		} else if (traces[i].trace.kind != OWL_TRACE_KIND_TIMESTAMP &&
			   traces[i].trace.kind != OWL_TRACE_KIND_PCHI) {
			/* Flame output needs the complete frame info */
			populate_frame(traces, ntraces, i,
				       &curr_callstack->frames[from_frame],
				       &pchi[from_frame],
				       from_frame, pchi_traces, npchitraces);
			to_frame++;

			switch (traces[i].trace.kind) {
			case OWL_TRACE_KIND_UECALL:
				if (to_frame != 1) {
					fprintf(stdwarn, "WARNING: trace %lu to_frame=%d but expect 1\n", i, to_frame);
				}
				break;
			case OWL_TRACE_KIND_SECALL:
				if (to_frame != 2)
					fprintf(stdwarn, "WARNING: trace %lu to_frame=%d but expect 2\n", i, to_frame);
				break;
			}

			curr_callstack->frames[from_frame].pchi = pchi[from_frame];
			curr_callstack->frames[to_frame].enter_trace = &traces[i];
		}
		if (!(0 <= to_frame && to_frame < 3)) {
			fprintf(stdwarn, "WARNING: trace %lu to_frame=%d, adjusting\n", i, to_frame);
			to_frame = max (to_frame, 0);
			to_frame = min (to_frame, 2);
		}
		if (!(0 <= from_frame && from_frame < 3)) {
			fprintf(stdwarn, "WARNING: trace %lu from_frame=%d, adjusting\n", i, from_frame);
			from_frame = max (from_frame, 0);
			from_frame = min (from_frame, 2);
		}
		assert(0 <= to_frame && to_frame < 3);
		assert(0 <= from_frame && from_frame < 3);

		curr_callstack->frameno = to_frame;

		{
			struct print_args args = {
				.trace			= &traces[i],
				.maps			= maps,
				.num_map_entries	= num_map_entries,
				.pc_bits		= 39,
				.sign_extend_pc		= true,
				.delim			= '\n',
				.start_time		= traces[0].timestamp,
				.sysroot		= sysroot,
				.cpu			= cpu
			};
			printer->print_trace[traces[i].trace.kind](&args, curr_callstack);
		}

		if (traces[i].trace.kind == OWL_TRACE_KIND_RETURN) {
			/* HACK */
			curr_callstack->frames[from_frame].enter_trace =
				&default_enter0;
			curr_callstack->frames[from_frame].return_trace = NULL;
		}
	}

	/*
	 * Print all scheduling events that occured after H/W tracing
	 * was disabled.
	 * TODO: This should be done for FLAME too.
	 */
	const struct owl_sched_info_full *next_sched;
	while (++prev_sched < end_sched - 1) {
		next_sched = prev_sched;
		while (++next_sched < end_sched) {
			if (next_sched == end_sched)
				break;
			if (next_sched->base.cpu == cpu)
				break;
		}
		if (next_sched == end_sched)
			break;
		printer->print_sched(prev_sched,
				prev_sched->base.timestamp - traces[0].timestamp,
				next_sched->base.timestamp - traces[0].timestamp,
				cpu, '\n');
	}
	/* Fake end time for last sched info entry. */
	printer->print_sched(prev_sched,
			prev_sched->base.timestamp - traces[0].timestamp,
			prev_sched->base.timestamp - traces[0].timestamp + 1,
			cpu, '\n');

	free(traces);
	free(pchi_traces);
}

static void
dump_trace(const struct owl_trace_file_header *file_header,
	   const uint8_t *tracebuf,
	   const uint8_t *sched_info_buf, size_t sched_info_size,
	   size_t sched_info_entries,
	   const struct owl_stream_info *stream_info,
	   struct owl_map_info *map_info, size_t map_info_size,
	   struct options *options, struct printer *printer)
{
	const char *sysroot = options->sysroot ?: DEFAULT_SYSROOT;
	int cpu_start, cpu_end, cpu;
	struct owl_sched_info_full *sched_info;
	size_t ntasks;
	struct owl_task *tasks;
	struct callstack *callstacks;
	const size_t num_map_entries = map_info_size / sizeof(*map_info);

	/* Unpack scheduling info to full format */
	if (!sched_info_entries)
		return;
	sched_info = calloc(sched_info_entries, sizeof(*sched_info));
	assert(sched_info != NULL);
	unpack_sched_info(sched_info, sched_info_buf, sched_info_size,
			  sched_info_entries);

	/* Count number of unique tasks */
	ntasks = unique_tasks(sched_info, sched_info_entries);
	if (!ntasks)
		goto out_free_sched_info;

	tasks = calloc(ntasks, sizeof(*tasks));
	callstacks = calloc(ntasks, sizeof(*callstacks));

	assert(tasks != NULL && callstacks != NULL);

	create_tasks(tasks, ntasks, sched_info, sched_info_entries);
	init_callstacks(callstacks, tasks, ntasks);

	/* Sort the map info so we can binary search it */
	sort_maps(map_info, num_map_entries);

	source_info_hashmap = source_hash_init();

	/* Set core range to dump (all or one) */
	if (options->have_cpu) {
		cpu_start = options->cpu;
		cpu_end = options->cpu + 1;
	} else {
		cpu_start = 0;
		cpu_end = file_header->num_cpus;
	}
	/* Dump */
	for (cpu = cpu_start; cpu < cpu_end; cpu++) {
		const struct owl_stream_info *cpu_si = &stream_info[cpu];
		const uint8_t *trace_stream = &tracebuf[cpu_si->offs];
		const size_t trace_stream_size = cpu_si->size;

		dump_trace_one_cpu(trace_stream, trace_stream_size,
				   sched_info, sched_info_entries,
				   callstacks, ntasks,
				   map_info, map_info_size,
				   sysroot, printer, cpu);
	}

	source_hash_fini(source_info_hashmap);

	free(callstacks);
	free(tasks);
out_free_sched_info:
	free(sched_info);
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
		"usage: %s [--verbose | -v] [[--format | -f] [normal | flame | kutrace]] [[--cpu | -c] cpu] [[--sysroot | -s] sysroot] [--help | -h] FILE\n",
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
			{"sysroot", required_argument, NULL,  's' },
			{"help",    no_argument,       NULL,  'h' },
			{0,         0,                 NULL,  0   }
		};

		c = getopt_long(argc, argv, "vf:c:s:h", long_options,
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

static void
print_file_header(const struct owl_trace_file_header *fh)
{
	printf("FILE HEADER\n");
	printf("magic:\t\t\t%lx\n", fh->magic);
	printf("trace_format:\t\t%u\n", fh->trace_format);
	printf("host_name:\t\t%s\n", fh->hostname);
	printf("start_time:\t\t%lu\n", fh->start_time);
	printf("stop_time:\t\t%lu\n", fh->stop_time);
	printf("num_cpus:\t\t%u\n", fh->num_cpus);
	printf("stream_info_size:\t%lu\n", fh->stream_info_size);
	printf("stream_info_offs:\t%lu\n", fh->stream_info_offs);
	printf("tracebuf_size:\t\t%lu\n", fh->tracebuf_size);
	printf("tracebuf_offs:\t\t%lu\n", fh->tracebuf_offs);
	printf("sched_info_size:\t%lu\n", fh->sched_info_size);
	printf("sched_info_entries:\t%lu\n", fh->sched_info_entries);
	printf("sched_info_offs:\t%lu\n", fh->sched_info_offs);
	printf("map_info_size:\t\t%lu\n", fh->map_info_size);
	printf("map_info_offs:\t\t%lu\n", fh->map_info_offs);
	printf("sentinel:\t\t%lx\n", fh->sentinel);
	printf("==================================================\n");
}

static void
print_stream_info(const struct owl_stream_info *si, uint64_t size)
{
	printf("TRACE STREAMS\n");
	while (si && size) {
		printf("cpu:\t\t\t%u\n", si->cpu);
		printf("offs:\t\t\t%llu\n", si->offs);
		printf("size:\t\t\t%llu\n", si->size);
		size -= min(size, sizeof(*si));
		si++;
	}
	printf("==================================================\n");
}

int
main(int argc, char *argv[])
{
	const uint8_t *buf, *tracebuf, *payload;
	const struct owl_trace_file_header *file_header;
	const uint8_t *sched_info_buf;
	const struct owl_stream_info *stream_info;
	struct owl_map_info *map_info;
	int fd;
	size_t buf_size, sched_info_size, sched_info_entries;
	size_t map_info_size;
	struct options options = { 0 };
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

	file_header = (const struct owl_trace_file_header *) buf;
	if (file_header->magic != OWL_TRACE_FILE_HEADER_MAGIC) {
		fprintf(stderr, "Wrong file header sentinel\n");
		print_usage_and_die(argc, argv, EXIT_FAILURE);
	}
	if (file_header->sentinel != OWL_TRACE_FILE_HEADER_SENTINEL) {
		fprintf(stderr, "Wrong file header sentinel\n");
		print_usage_and_die(argc, argv, EXIT_FAILURE);
	}
	if (file_header->num_cpus < 1) {
		fprintf(stderr, "No CPU streams in file header\n");
		print_usage_and_die(argc, argv, EXIT_FAILURE);
	}
	if (options.cpu >= file_header->num_cpus) {
		fprintf(stderr, "cpu not in trace\n");
		print_usage_and_die(argc, argv, EXIT_FAILURE);
	}

	if (file_header->stream_info_size <
	    sizeof(struct owl_stream_info) * file_header->num_cpus) {
		fprintf(stderr, "stream_info_size too small\n");
		print_usage_and_die(argc, argv, EXIT_FAILURE);
	}

	payload = (const uint8_t *) &file_header[1];
	stream_info = (const struct owl_stream_info *)
		      (payload + file_header->stream_info_offs);
	tracebuf = payload + file_header->tracebuf_offs;
	sched_info_buf = (const uint8_t *)
			 (payload + file_header->sched_info_offs);
	sched_info_size = file_header->sched_info_size;
	sched_info_entries = file_header->sched_info_entries;
	map_info = (struct owl_map_info *)
		   (payload + file_header->map_info_offs);
	map_info_size = file_header->map_info_size;

	if (options.verbose && options.outfmt == OUTFMT_NORMAL) {
		print_file_header(file_header);
		print_stream_info(stream_info, file_header->stream_info_size);
	}

	switch (options.outfmt) {
	default:
		printer = options.verbose ? &default_verbose_printer :
					    &default_printer;
		break;
	case OUTFMT_FLAME:
		printer = &flame_printer;
		break;
	case OUTFMT_KUTRACE_EVENT:
		printer = &kutrace_json_printer;
		break;
	}

	if (printer->print_prologue)
		printer->print_prologue(file_header);

	dump_trace(file_header, tracebuf,
		   sched_info_buf, sched_info_size, sched_info_entries,
		   stream_info,
		   map_info, map_info_size,
		   &options, printer);

	if (printer->print_epilogue)
		printer->print_epilogue(file_header);

	munmap((void *) buf, buf_size);
	close(fd);

	return 0;
}
