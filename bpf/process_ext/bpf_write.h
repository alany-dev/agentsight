/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __PROCESS_NEW_BPF_WRITE_H
#define __PROCESS_NEW_BPF_WRITE_H

/*
 * write() syscall tracing: enter/exit pairing for byte count aggregation.
 * write_fd_map is defined in process_new.bpf.c (temporary context, not aggregation).
 * Aggregation goes into event_agg_map with detail="fd=N".
 */

SEC("tp/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
	if (!trace_fs_mutations)
		return 0;
	if (!is_pid_tracked())
		return 0;

	u64 id = bpf_get_current_pid_tgid();
	int fd = (int)ctx->args[0];
	bpf_map_update_elem(&write_fd_map, &id, &fd, BPF_ANY);
	return 0;
}

SEC("tp/syscalls/sys_exit_write")
int trace_write_exit(struct trace_event_raw_sys_exit *ctx)
{
	if (!trace_fs_mutations)
		return 0;

	long ret = ctx->ret;
	if (ret <= 0)
		return 0;

	u64 id = bpf_get_current_pid_tgid();
	int *fd_ptr = bpf_map_lookup_elem(&write_fd_map, &id);
	if (!fd_ptr)
		return 0;

	int fd = *fd_ptr;
	bpf_map_delete_elem(&write_fd_map, &id);

	struct agg_key key = {};
	key.pid = id >> 32;
	key.event_type = EVENT_TYPE_WRITE;
	format_fd_detail(key.detail, sizeof(key.detail), fd);

	update_agg_map(&key, 1, (u64)ret);
	return 0;
}

#endif /* __PROCESS_NEW_BPF_WRITE_H */
