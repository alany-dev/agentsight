// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* process_new.c — Extended process tracer with BPF map aggregation.
 * Independent from process.c; copies core logic + adds flush loop.
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "process.h"
#include "process_new.h"
#include "process_new.skel.h"
#include "process_utils.h"
#include "process_filter.h"
#include "process_ext/map_flush.h"
#include "process_ext/mem_info.h"
#include "process_ext/resource_sampler.h"

#define MAX_COMMAND_LIST 256
#define FILE_DEDUP_WINDOW_NS 60000000000ULL  /* 60 seconds */
#define MAX_FILE_HASHES 1024
#define MAX_PID_LIMITS 256
#define MAX_DISTINCT_FILES_PER_SEC 30

#define POLL_TIMEOUT_MS  1000   /* ring buffer poll timeout */
#define FLUSH_INTERVAL_S 5      /* BPF map flush interval */

/* ========== FILE_OPEN dedup (copied from process.c) ========== */

struct per_second_limit {
	pid_t pid;
	uint64_t current_second;
	uint32_t distinct_file_count;
	bool should_warn_next;
};

struct file_hash_entry {
	uint64_t hash;
	uint64_t timestamp_ns;
	uint32_t count;
	pid_t pid;
	char comm[TASK_COMM_LEN];
	char filepath[MAX_FILENAME_LEN];
	int flags;
};

static struct file_hash_entry file_hashes[MAX_FILE_HASHES];
static int hash_count = 0;
static struct per_second_limit pid_limits[MAX_PID_LIMITS];
static int pid_limit_count = 0;

/* ========== Configuration ========== */

static struct env {
	bool verbose;
	long min_duration_ms;
	char *command_list[MAX_COMMAND_LIST];
	int command_count;
	enum filter_mode filter_mode;
	pid_t pid;
	/* new feature flags */
	bool trace_fs;
	bool trace_net;
	bool trace_signals;
	bool trace_mem;
	bool trace_cow;
	bool trace_resources;
	bool resource_detail;
	int sample_interval_ms;
	char cgroup_path[256];
} env = {
	.verbose = false,
	.min_duration_ms = 0,
	.command_count = 0,
	.filter_mode = FILTER_MODE_PROC,
	.pid = 0,
	.sample_interval_ms = 1000,
};

static struct pid_tracker pid_tracker;

/* BPF skeleton and map FDs (set in main, used in handle_event) */
static struct process_new_bpf *g_skel;
static int g_agg_map_fd = -1;
static int g_tracked_pids_fd = -1;
static int g_overflow_fd = -1;
static int g_exit_mem_fd = -1;

/* Page size for memory info */
static long page_size_kb;

/* Target PID for resource sampling (set from -p or first matched process) */
static pid_t g_resource_target_pid = 0;

const char *argp_program_version = "process-new-tracer 1.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"Extended BPF process tracer with aggregated event tracking.\n"
"\n"
"Compatible with process tracer + additional tracing capabilities.\n"
"\n"
"USAGE: ./process_new [-d <min-duration-ms>] [-c <cmd>] [-p <pid>] [-m <mode>] [-v]\n"
"       [--trace-fs] [--trace-net] [--trace-signals] [--trace-mem] [--trace-cow] [--trace-all]\n";

enum {
	OPT_TRACE_FS = 256,
	OPT_TRACE_NET,
	OPT_TRACE_SIGNALS,
	OPT_TRACE_MEM,
	OPT_TRACE_COW,
	OPT_TRACE_ALL,
	OPT_TRACE_RESOURCES,
	OPT_RESOURCE_DETAIL,
	OPT_SAMPLE_INTERVAL,
	OPT_CGROUP,
};

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{ "commands", 'c', "COMMAND-LIST", 0, "Comma-separated list of commands to trace" },
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "mode", 'm', "FILTER-MODE", 0, "Filter mode: 0=all, 1=proc, 2=filter (default=2)" },
	{ "all", 'a', NULL, 0, "Deprecated: use -m 0 instead" },
	{ "trace-fs", OPT_TRACE_FS, NULL, 0, "Trace filesystem mutations (delete, rename, mkdir, write, truncate, chdir)" },
	{ "trace-net", OPT_TRACE_NET, NULL, 0, "Trace network operations (bind, listen, connect)" },
	{ "trace-signals", OPT_TRACE_SIGNALS, NULL, 0, "Trace process coordination (setpgid, setsid, kill, fork)" },
	{ "trace-mem", OPT_TRACE_MEM, NULL, 0, "Trace shared memory (mmap MAP_SHARED)" },
	{ "trace-cow", OPT_TRACE_COW, NULL, 0, "Trace CoW page faults (kprobe/do_wp_page, high overhead)" },
	{ "trace-all", OPT_TRACE_ALL, NULL, 0, "Enable all tracing except --trace-cow" },
	{ "trace-resources", OPT_TRACE_RESOURCES, NULL, 0, "Sample memory/CPU periodically for tracked processes" },
	{ "resource-detail", OPT_RESOURCE_DETAIL, NULL, 0, "Also output per-process resource detail (requires --trace-resources)" },
	{ "sample-interval", OPT_SAMPLE_INTERVAL, "MS", 0, "Resource sampling interval in milliseconds (default: 1000)" },
	{ "cgroup", OPT_CGROUP, "PATH", 0, "Cgroup v2 path for resource sampling (auto-detected if omitted)" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	char *token;
	char *saveptr;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'p':
		errno = 0;
		env.pid = (pid_t)strtol(arg, NULL, 10);
		if (errno || env.pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.filter_mode = FILTER_MODE_FILTER;
		break;
	case 'a':
		env.filter_mode = FILTER_MODE_ALL;
		break;
	case 'm': {
		errno = 0;
		int mode = strtol(arg, NULL, 10);
		if (errno || mode < 0 || mode > 2) {
			fprintf(stderr, "Invalid filter mode: %s (must be 0, 1, or 2)\n", arg);
			argp_usage(state);
		}
		env.filter_mode = (enum filter_mode)mode;
		break;
	}
	case 'c': {
		env.filter_mode = FILTER_MODE_FILTER;
		char *arg_copy = strdup(arg);
		if (!arg_copy) {
			fprintf(stderr, "Memory allocation failed\n");
			return ARGP_ERR_UNKNOWN;
		}
		token = strtok_r(arg_copy, ",", &saveptr);
		while (token && env.command_count < MAX_COMMAND_LIST) {
			while (*token == ' ' || *token == '\t') token++;
			char *end = token + strlen(token) - 1;
			while (end > token && (*end == ' ' || *end == '\t')) end--;
			*(end + 1) = '\0';
			if (strlen(token) > 0) {
				env.command_list[env.command_count] = strdup(token);
				if (!env.command_list[env.command_count]) {
					fprintf(stderr, "Memory allocation failed\n");
					free(arg_copy);
					return ARGP_ERR_UNKNOWN;
				}
				env.command_count++;
			}
			token = strtok_r(NULL, ",", &saveptr);
		}
		free(arg_copy);
		break;
	}
	case OPT_TRACE_FS:
		env.trace_fs = true;
		break;
	case OPT_TRACE_NET:
		env.trace_net = true;
		break;
	case OPT_TRACE_SIGNALS:
		env.trace_signals = true;
		break;
	case OPT_TRACE_MEM:
		env.trace_mem = true;
		break;
	case OPT_TRACE_COW:
		env.trace_cow = true;
		break;
	case OPT_TRACE_ALL:
		env.trace_fs = true;
		env.trace_net = true;
		env.trace_signals = true;
		env.trace_mem = true;
		/* trace_cow NOT included in trace-all */
		break;
	case OPT_TRACE_RESOURCES:
		env.trace_resources = true;
		break;
	case OPT_RESOURCE_DETAIL:
		env.resource_detail = true;
		break;
	case OPT_SAMPLE_INTERVAL:
		env.sample_interval_ms = atoi(arg);
		if (env.sample_interval_ms < 10)
			env.sample_interval_ms = 10;
		break;
	case OPT_CGROUP:
		strncpy(env.cgroup_path, arg, sizeof(env.cgroup_path) - 1);
		env.cgroup_path[sizeof(env.cgroup_path) - 1] = '\0';
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

/* ========== Rate limiting (copied from process.c) ========== */

static bool should_rate_limit_file(const struct event *e, uint64_t timestamp_ns, bool *add_warning)
{
	uint64_t current_second = timestamp_ns / 1000000000ULL;
	*add_warning = false;

	struct per_second_limit *limit = NULL;
	for (int i = 0; i < pid_limit_count; i++) {
		if (pid_limits[i].pid == e->pid) {
			limit = &pid_limits[i];
			break;
		}
	}

	if (!limit && pid_limit_count < MAX_PID_LIMITS) {
		limit = &pid_limits[pid_limit_count++];
		limit->pid = e->pid;
		limit->current_second = current_second;
		limit->distinct_file_count = 0;
		limit->should_warn_next = false;
	}

	if (!limit) return false;

	if (limit->current_second != current_second) {
		if (limit->should_warn_next) {
			*add_warning = true;
			limit->should_warn_next = false;
		}
		limit->current_second = current_second;
		limit->distinct_file_count = 0;
	}

	limit->distinct_file_count++;
	if (limit->distinct_file_count > MAX_DISTINCT_FILES_PER_SEC) {
		limit->should_warn_next = true;
		return true;
	}

	return false;
}

/* ========== FILE_OPEN print + dedup (copied from process.c) ========== */

static void print_file_open_event(const struct event *e, uint64_t timestamp_ns, uint32_t count, const char *extra_fields)
{
	printf("{");
	printf("\"timestamp\":%llu,", (unsigned long long)timestamp_ns);
	printf("\"event\":\"FILE_OPEN\",");
	printf("\"comm\":\"%s\",", e->comm);
	printf("\"pid\":%d,", e->pid);
	printf("\"count\":%u,", count);
	printf("\"filepath\":\"%s\",", e->file_op.filepath);
	printf("\"flags\":%d", e->file_op.flags);
	if (extra_fields && strlen(extra_fields) > 0)
		printf(",%s", extra_fields);
	printf("}\n");
	fflush(stdout);
}

static uint64_t hash_file_open(const struct event *e)
{
	uint64_t hash = 5381;
	hash = ((hash << 5) + hash) + e->pid;
	const char *str = e->file_op.filepath;
	while (*str)
		hash = ((hash << 5) + hash) + *str++;
	return hash;
}

static uint32_t get_file_open_count(const struct event *e, uint64_t timestamp_ns, char *warning_msg, size_t warning_msg_size)
{
	if (e->type != EVENT_TYPE_FILE_OPERATION || !e->file_op.is_open)
		return 1;

	warning_msg[0] = '\0';
	bool add_warning = false;
	if (should_rate_limit_file(e, timestamp_ns, &add_warning))
		return 0;

	if (add_warning)
		snprintf(warning_msg, warning_msg_size, "\"rate_limit_warning\":\"Previous second exceeded %d file limit\"", MAX_DISTINCT_FILES_PER_SEC);

	uint64_t hash = hash_file_open(e);

	/* Clean expired entries */
	for (int i = 0; i < hash_count; i++) {
		if (timestamp_ns - file_hashes[i].timestamp_ns > FILE_DEDUP_WINDOW_NS) {
			if (file_hashes[i].count > 1) {
				struct event fake_event = {
					.type = EVENT_TYPE_FILE_OPERATION,
					.pid = file_hashes[i].pid,
					.file_op = { .fd = -1, .flags = file_hashes[i].flags, .is_open = true }
				};
				strncpy(fake_event.comm, file_hashes[i].comm, TASK_COMM_LEN - 1);
				fake_event.comm[TASK_COMM_LEN - 1] = '\0';
				strncpy(fake_event.file_op.filepath, file_hashes[i].filepath, MAX_FILENAME_LEN - 1);
				fake_event.file_op.filepath[MAX_FILENAME_LEN - 1] = '\0';
				print_file_open_event(&fake_event, timestamp_ns, file_hashes[i].count, "\"window_expired\":true");
			}
			file_hashes[i] = file_hashes[hash_count - 1];
			hash_count--;
			i--;
		}
	}

	/* Check for existing hash */
	for (int i = 0; i < hash_count; i++) {
		if (file_hashes[i].hash == hash) {
			file_hashes[i].count++;
			file_hashes[i].timestamp_ns = timestamp_ns;
			return 0;
		}
	}

	/* Add new entry */
	if (hash_count < MAX_FILE_HASHES) {
		file_hashes[hash_count].hash = hash;
		file_hashes[hash_count].timestamp_ns = timestamp_ns;
		file_hashes[hash_count].count = 1;
		file_hashes[hash_count].pid = e->pid;
		strncpy(file_hashes[hash_count].comm, e->comm, TASK_COMM_LEN - 1);
		file_hashes[hash_count].comm[TASK_COMM_LEN - 1] = '\0';
		strncpy(file_hashes[hash_count].filepath, e->file_op.filepath, MAX_FILENAME_LEN - 1);
		file_hashes[hash_count].filepath[MAX_FILENAME_LEN - 1] = '\0';
		file_hashes[hash_count].flags = e->file_op.flags;
		hash_count++;
	}

	return 1;
}

static void flush_pid_file_opens(pid_t pid, uint64_t timestamp_ns)
{
	for (int i = 0; i < hash_count; i++) {
		if (file_hashes[i].pid == pid && file_hashes[i].count > 1) {
			struct event fake_event = {
				.type = EVENT_TYPE_FILE_OPERATION,
				.pid = file_hashes[i].pid,
				.file_op = { .fd = -1, .flags = file_hashes[i].flags, .is_open = true }
			};
			strncpy(fake_event.comm, file_hashes[i].comm, TASK_COMM_LEN - 1);
			fake_event.comm[TASK_COMM_LEN - 1] = '\0';
			strncpy(fake_event.file_op.filepath, file_hashes[i].filepath, MAX_FILENAME_LEN - 1);
			fake_event.file_op.filepath[MAX_FILENAME_LEN - 1] = '\0';
			print_file_open_event(&fake_event, timestamp_ns, file_hashes[i].count, "\"reason\":\"process_exit\"");
		}
	}

	for (int i = 0; i < hash_count; i++) {
		if (file_hashes[i].pid == pid) {
			file_hashes[i] = file_hashes[hash_count - 1];
			hash_count--;
			i--;
		}
	}
}

/* ========== Populate initial PIDs ========== */

static int populate_initial_pids(struct pid_tracker *tracker)
{
	DIR *proc_dir;
	struct dirent *entry;
	pid_t pid, ppid;
	char comm[TASK_COMM_LEN];
	int tracked_count = 0;

	proc_dir = opendir("/proc");
	if (!proc_dir)
		return -1;

	while ((entry = readdir(proc_dir)) != NULL) {
		if (strspn(entry->d_name, "0123456789") != strlen(entry->d_name))
			continue;
		pid = (pid_t)strtol(entry->d_name, NULL, 10);
		if (pid <= 0)
			continue;
		if (read_proc_comm(pid, comm, sizeof(comm)) != 0)
			continue;
		if (read_proc_ppid(pid, &ppid) != 0)
			continue;

		if (should_track_process(tracker, comm, pid, ppid)) {
			if (pid_tracker_add(tracker, pid, ppid)) {
				tracked_count++;
				/* Also add to BPF tracked_pids map */
				if (g_tracked_pids_fd >= 0) {
					uint32_t bpf_pid = pid;
					uint8_t val = 1;
					bpf_map_update_elem(g_tracked_pids_fd, &bpf_pid, &val, BPF_ANY);
				}
			}
		}
	}

	closedir(proc_dir);
	return tracked_count;
}

/* ========== Event handler ========== */

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct pid_tracker *tracker = (struct pid_tracker *)ctx;
	uint64_t timestamp_ns = e->timestamp_ns;

	switch (e->type) {
	case EVENT_TYPE_PROCESS:
		if (e->exit_event) {
			bool is_tracked = pid_tracker_is_tracked(tracker, e->pid);
			pid_tracker_remove(tracker, e->pid);

			/* Remove from BPF tracked_pids */
			if (g_tracked_pids_fd >= 0) {
				uint32_t bpf_pid = e->pid;
				bpf_map_delete_elem(g_tracked_pids_fd, &bpf_pid);
			}

			if (!is_tracked && tracker->filter_mode == FILTER_MODE_FILTER)
				break;

			printf("{\"timestamp\":%llu,\"event\":\"EXIT\","
			       "\"comm\":\"%s\",\"pid\":%d,\"ppid\":%d",
			       (unsigned long long)timestamp_ns, e->comm, e->pid, e->ppid);
			printf(",\"exit_code\":%u", e->exit_code);
			if (e->duration_ns)
				printf(",\"duration_ms\":%llu", (unsigned long long)(e->duration_ns / 1000000));

			/* Memory info at exit (from BPF exit_mem map) */
			if (g_exit_mem_fd >= 0) {
				uint32_t mem_pid = e->pid;
				struct exit_mem_info emem = {};
				if (bpf_map_lookup_elem(g_exit_mem_fd, &mem_pid, &emem) == 0) {
					printf(",\"vm_hwm_kb\":%llu",
					       (unsigned long long)(emem.hiwater_rss * page_size_kb));
					bpf_map_delete_elem(g_exit_mem_fd, &mem_pid);
				}
			}

			printf("}\n");
			fflush(stdout);

			/* Flush FILE_OPEN dedup for this PID */
			flush_pid_file_opens(e->pid, timestamp_ns);

			/* Flush BPF agg map entries for this PID */
			if (g_agg_map_fd >= 0)
				flush_pid_from_agg_map(g_agg_map_fd, e->pid);
		} else {
			if (should_track_process(tracker, e->comm, e->pid, e->ppid)) {
				pid_tracker_add(tracker, e->pid, e->ppid);

				/* Set resource sampling target from first matching EXEC */
				if (env.trace_resources && g_resource_target_pid == 0 &&
				    tracker->command_filter_count > 0 &&
				    command_matches_any_filter(e->comm, tracker->command_filters,
				                              tracker->command_filter_count)) {
					g_resource_target_pid = e->pid;
					/* Auto-detect cgroup path if not specified */
					if (env.cgroup_path[0] == '\0')
						detect_cgroup_path(e->pid, env.cgroup_path, sizeof(env.cgroup_path));
				}

				/* Add to BPF tracked_pids */
				if (g_tracked_pids_fd >= 0) {
					uint32_t bpf_pid = e->pid;
					uint8_t val = 1;
					bpf_map_update_elem(g_tracked_pids_fd, &bpf_pid, &val, BPF_ANY);
				}

				printf("{\"timestamp\":%llu,\"event\":\"EXEC\","
				       "\"comm\":\"%s\",\"pid\":%d,\"ppid\":%d",
				       (unsigned long long)timestamp_ns, e->comm, e->pid, e->ppid);
				printf(",\"filename\":\"%s\"", e->filename);
				printf(",\"full_command\":\"%s\"", e->full_command);

				/* Memory info at exec */
				struct proc_mem_info mem;
				if (read_proc_mem_info(e->pid, &mem)) {
					printf(",\"rss_kb\":%ld,\"shared_kb\":%ld",
					       mem.rss_pages * page_size_kb,
					       mem.shared_pages * page_size_kb);
				}

				printf("}\n");
				fflush(stdout);
			} else if (tracker->filter_mode == FILTER_MODE_FILTER) {
				break;
			} else {
				if (tracker->filter_mode == FILTER_MODE_PROC)
					pid_tracker_add(tracker, e->pid, e->ppid);

				printf("{\"timestamp\":%llu,\"event\":\"EXEC\","
				       "\"comm\":\"%s\",\"pid\":%d,\"ppid\":%d",
				       (unsigned long long)timestamp_ns, e->comm, e->pid, e->ppid);
				printf(",\"filename\":\"%s\"", e->filename);
				printf(",\"full_command\":\"%s\"", e->full_command);
				printf("}\n");
				fflush(stdout);
			}
		}
		break;

	case EVENT_TYPE_BASH_READLINE:
		if (!should_report_bash_readline(tracker, e->pid))
			break;
		printf("{\"timestamp\":%llu,\"event\":\"BASH_READLINE\","
		       "\"comm\":\"%s\",\"pid\":%d,\"command\":\"%s\"}\n",
		       (unsigned long long)timestamp_ns, e->comm, e->pid, e->command);
		fflush(stdout);
		break;

	case EVENT_TYPE_FILE_OPERATION:
		if (!e->file_op.is_open)
			break;
		if (!should_report_file_ops(tracker, e->pid))
			break;
		{
			char warning_msg[128];
			uint32_t count = get_file_open_count(e, timestamp_ns, warning_msg, sizeof(warning_msg));
			if (count == 0)
				break;
			print_file_open_event(e, timestamp_ns, count, strlen(warning_msg) > 0 ? warning_msg : NULL);
		}
		break;

	default:
		printf("{\"timestamp\":%llu,\"event\":\"UNKNOWN\",\"event_type\":%d}\n",
		       (unsigned long long)timestamp_ns, e->type);
		fflush(stdout);
		break;
	}

	return 0;
}

/* ========== Main ========== */

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct process_new_bpf *skel;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	page_size_kb = sysconf(_SC_PAGESIZE) / 1024;
	if (page_size_kb <= 0)
		page_size_kb = 4;

	pid_tracker_init(&pid_tracker, env.command_list, env.command_count, env.filter_mode, env.pid);
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = process_new_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Set feature flags */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
	skel->rodata->trace_fs_mutations = env.trace_fs;
	skel->rodata->trace_network = env.trace_net;
	skel->rodata->trace_signals = env.trace_signals;
	skel->rodata->trace_memory = env.trace_mem;
	skel->rodata->trace_cow = env.trace_cow;

	/* Enable BPF-side PID filtering when command/pid filters are set */
	bool need_pid_filter = (env.filter_mode == FILTER_MODE_FILTER) &&
			       (env.command_count > 0 || env.pid > 0);
	skel->rodata->filter_pids = need_pid_filter;

	err = process_new_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	g_skel = skel;
	g_agg_map_fd = bpf_map__fd(skel->maps.event_agg_map);
	g_tracked_pids_fd = bpf_map__fd(skel->maps.tracked_pids);
	g_overflow_fd = bpf_map__fd(skel->maps.agg_overflow_count);
	g_exit_mem_fd = bpf_map__fd(skel->maps.exit_mem);

	int tracked_count = populate_initial_pids(&pid_tracker);
	if (tracked_count < 0) {
		fprintf(stderr, "Failed to populate initial PIDs\n");
		goto cleanup;
	}

	if (env.verbose) {
		fprintf(stderr, "Loaded process_new: trace_fs=%d trace_net=%d trace_signals=%d "
			"trace_mem=%d trace_cow=%d filter_pids=%d initial_tracked=%d\n",
			env.trace_fs, env.trace_net, env.trace_signals,
			env.trace_mem, env.trace_cow, need_pid_filter, tracked_count);
	}

	err = process_new_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &pid_tracker, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Set resource target PID from -p option if specified */
	if (env.trace_resources && env.pid > 0)
		g_resource_target_pid = env.pid;

	/* Auto-detect cgroup path if --trace-resources but no --cgroup specified */
	if (env.trace_resources && !env.cgroup_path[0]) {
		pid_t detect_pid = env.pid > 0 ? env.pid : getpid();
		if (detect_cgroup_path(detect_pid, env.cgroup_path, sizeof(env.cgroup_path))) {
			if (env.verbose)
				fprintf(stderr, "Auto-detected cgroup: %s\n", env.cgroup_path);
		}
	}

	/* Main loop: poll ring buffer + periodic flush + resource sampling */
	uint64_t last_flush_time = 0;
	uint64_t last_sample_ms = 0;

	while (!exiting) {
		/* Use shorter poll timeout if sampling at high frequency */
		int poll_ms = POLL_TIMEOUT_MS;
		if (env.trace_resources && env.sample_interval_ms < poll_ms)
			poll_ms = env.sample_interval_ms;

		err = ring_buffer__poll(rb, poll_ms);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}

		/* Check flush timer */
		uint64_t now = (uint64_t)time(NULL);
		if (now - last_flush_time >= FLUSH_INTERVAL_S) {
			if (g_agg_map_fd >= 0)
				flush_agg_map(g_agg_map_fd);
			if (g_overflow_fd >= 0)
				check_overflow(g_overflow_fd);
			last_flush_time = now;
		}

		/* Resource sampling at configured interval */
		if (env.trace_resources && g_resource_target_pid > 0) {
			struct timespec ts;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			uint64_t now_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
			if (now_ms - last_sample_ms >= (uint64_t)env.sample_interval_ms) {
				sample_resources(g_resource_target_pid, page_size_kb,
						 env.resource_detail, env.cgroup_path);
				last_sample_ms = now_ms;
			}
		}
	}

	/* Final flush on exit */
	if (g_agg_map_fd >= 0)
		flush_agg_map(g_agg_map_fd);

cleanup:
	ring_buffer__free(rb);
	process_new_bpf__destroy(skel);
	for (int i = 0; i < env.command_count; i++)
		free(env.command_list[i]);
	hash_count = 0;
	pid_limit_count = 0;

	return err < 0 ? -err : 0;
}
