#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#if 0
/* When things stabilize and we can move it to the sysroot */
#include <linux/owl.h>
#else
#define __user /* This is stripped from uapi headers by linux */
#include "owl.h"
#endif
#include "owl-user.h"

#define max(x,y) (x > y ? x : y)

enum command {
	CMD_START,
	CMD_STOP,
	CMD_DUMP,
	CMD_INVALID,
	CMD_NR_COMMANDS = CMD_INVALID,
};

struct options {
	enum command cmd;
	char *path;
	bool ignore_illegal_insn;
};
#define INIT_OPTIONS { \
	.cmd = CMD_NR_COMMANDS, \
	.path = "/dev/tracectrl0", \
	.ignore_illegal_insn = true } /* TODO: This should be configurable */

struct state {
	int fd;
	char *path;
};
#define INIT_STATE { .fd = -1, }

const char *str_to_cmd[CMD_NR_COMMANDS + 1] = {
	[CMD_START]		= "start",
	[CMD_STOP]		= "stop",
	[CMD_DUMP]		= "dump",
	[CMD_NR_COMMANDS]	= NULL,
};

/* Return 0 on success */
static int
parse_cmdline(int argc, char *argv[], struct options *options)
{
	enum command i;

	if (argc < 3)
		return 1;

	if (strcmp("trace", argv[1]))
		return 1;

	for (i = 0; str_to_cmd[i]; i++) {
		if (!strcmp(str_to_cmd[i], argv[2]))
			break;
	}
	options->cmd = i;

	return options->cmd >= CMD_NR_COMMANDS;
}

static int
do_config(struct options *options, struct state *state)
{
	struct owl_config config = { 0 };

	config.ignore_illegal_insn = options->ignore_illegal_insn;
	return ioctl(state->fd, OWL_IOCTL_CONFIG, &config);
}

static int
do_start(struct options *options, struct state *state)
{
	int err;

	err = do_config(options, state);
	if (err)
		return err;

	return ioctl(state->fd, OWL_IOCTL_ENABLE);
}

static int
do_stop(struct options *options, struct state *state)
{
	(void)options;

	return ioctl(state->fd, OWL_IOCTL_DISABLE);
}

static int
do_dump(struct options *options, struct state *state)
{
	(void)options;

	int ret = 0;
	uint64_t offs;
	struct owl_status status = { 0 };
	struct owl_trace_header header = { 0 };
	struct owl_trace_file_header file_header = { 0 };

	ret = ioctl(state->fd, OWL_IOCTL_STATUS, &status);
	if (ret) {
		perror("status");
		return ret;
	}

	header.max_tracebuf_size = status.tracebuf_size;
	header.max_sched_info_size = status.sched_info_size;
	header.max_map_info_size = status.map_info_size;
	header.max_stream_info_size = status.stream_info_size;

	header.streaminfobuf = calloc(1, header.max_stream_info_size);
	if (!header.streaminfobuf) {
		perror("calloc");
		ret = 1;
		goto out;
	}
	header.tracebuf = calloc(1, header.max_tracebuf_size);
	if (!header.tracebuf) {
		perror("calloc");
		ret = 2;
		goto free_streaminfobuf;
	}
	header.schedinfobuf = calloc(1, header.max_sched_info_size);
	if (!header.schedinfobuf) {
		perror("calloc");
		ret = 3;
		goto free_tracebuf;
	}
	header.mapinfobuf = calloc(1, header.max_map_info_size);
	if (!header.mapinfobuf) {
		perror("calloc");
		ret = 4;
		goto free_schedinfobuf;
	}

	ret = ioctl(state->fd, OWL_IOCTL_DUMP, &header);
	if (ret) {
		perror("dump");
		goto free_mapinfobuf;
	}

	file_header.magic		= OWL_TRACE_FILE_HEADER_MAGIC;
	file_header.trace_format	= header.trace_format;
	file_header.num_cpus		= max(1,
					      header.stream_info_size /
					      sizeof(struct owl_stream_info));
	file_header.stream_info_size	= header.stream_info_size;
	file_header.tracebuf_size	= header.tracebuf_size;
	file_header.sched_info_size	= header.sched_info_size;
	file_header.map_info_size	= header.map_info_size;
	offs = 0;
	file_header.stream_info_offs	= offs;
	offs += header.stream_info_size;
	file_header.tracebuf_offs	= offs;
	offs += header.tracebuf_size;
	file_header.sched_info_offs	= offs;
	offs += header.sched_info_size;
	file_header.map_info_offs	= offs;
	file_header.sentinel		= OWL_TRACE_FILE_HEADER_SENTINEL;

	fwrite(&file_header, sizeof(file_header), 1, stdout);
	fwrite(header.streaminfobuf, header.stream_info_size, 1, stdout);
	fwrite(header.tracebuf, header.tracebuf_size, 1, stdout);
	fwrite(header.schedinfobuf, header.sched_info_size, 1, stdout);
	fwrite(header.mapinfobuf, header.map_info_size, 1, stdout);

free_mapinfobuf:
	free(header.mapinfobuf);
free_schedinfobuf:
	free(header.schedinfobuf);
free_tracebuf:
	free(header.tracebuf);
free_streaminfobuf:
	free(header.streaminfobuf);
out:
	return ret;
}

static int
(* const dispatch[CMD_NR_COMMANDS]) (struct options *, struct state *) = {
	[CMD_START]	= do_start,
	[CMD_STOP]	= do_stop,
	[CMD_DUMP]	= do_dump,
};

static int
init(struct options *options, struct state *state)
{
	int ret;

	ret = open(options->path, O_RDWR);
	if (ret < 0) {
		perror(options->path);
	} else {
		state->fd = ret;
		ret = 0;
	}

	return ret;
}

static int
fini(struct options *options, struct state *state)
{
	(void)options;

	if (state->fd > -1) {
		close(state->fd);
		state->fd = -1;
	}

	return 0;
}

void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s trace [start|stop|dump]\n", argv0);
}

int main(int argc, char *argv[])
{
	int ret;

	struct options options = INIT_OPTIONS;
	struct state state = INIT_STATE;

	if (parse_cmdline(argc, argv, &options)) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	ret = init(&options, &state);
	if (ret)
		return ret;

	ret = dispatch[options.cmd](&options, &state);
	if (ret)
		usage(argv[0]);

	fini(&options, &state);
	return ret;
}
