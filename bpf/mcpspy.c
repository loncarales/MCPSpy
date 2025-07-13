// SPDX-License-Identifier: GPL-2.0-only
// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_BUF_SIZE 16 * 1024
#define TASK_COMM_LEN 16

// Event types
#define EVENT_READ 1
#define EVENT_WRITE 2

// Event structure sent to userspace
struct event {
    __u32 pid;
    __u8 comm[TASK_COMM_LEN];
    __u8 event_type;
    __u32 size;
    __u32 buf_size;
    __u8 buf[MAX_BUF_SIZE];
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4MB buffer
} events SEC(".maps");

// Checking if the buffer starts with '{', while ignoring whitespace.
static __always_inline bool is_mcp_data(const char *buf, __u32 size) {
    if (size < 1)
        return false;

    char check[8];
    if (bpf_probe_read(check, sizeof(check), buf) != 0) {
        return false;
    }

// Check the first 8 bytes for the first non-whitespace character being '{'
#pragma unroll
    for (int i = 0; i < 8; i++) {
        char c = check[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }
        if (c == '{') {
            return true;
        }
        break;
    }
    return false;
}

SEC("fexit/vfs_read")
int BPF_PROG(exit_vfs_read, struct file *file, const char *buf, size_t count,
             loff_t *_pos, ssize_t ret) {
    if (ret <= 0) {
        // We logging only operations with data.
        return 0;
    }

    if (!is_mcp_data(buf, ret)) {
        return 0;
    }

    pid_t tgid = bpf_get_current_pid_tgid();

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) {
        bpf_printk("error: failed to reserve ring buffer for read event");
        return 0;
    }

    event->pid = tgid;
    event->event_type = EVENT_READ;
    event->size = ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->buf_size = ret < MAX_BUF_SIZE ? ret : MAX_BUF_SIZE;
    bpf_probe_read(event->buf, event->buf_size, buf);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(exit_vfs_write, struct file *file, const char *buf, size_t count,
             loff_t *_pos, size_t ret) {
    if (ret <= 0) {
        // We logging only operations with data.
        return 0;
    }

    if (!is_mcp_data(buf, ret)) {
        return 0;
    }

    pid_t tgid = bpf_get_current_pid_tgid();

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) {
        bpf_printk("error: failed to reserve ring buffer for write event");
        return 0;
    }

    event->pid = tgid;
    event->event_type = EVENT_WRITE;
    event->size = ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->buf_size = ret < MAX_BUF_SIZE ? ret : MAX_BUF_SIZE;
    bpf_probe_read(event->buf, event->buf_size, buf);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";