/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPISKBTRACE_H
#define _UAPISKBTRACE_H

#include <linux/types.h>
#include <linux/limits.h>

struct skb_user_trace_setup {
	char name[NAME_MAX];		/* input */
	int netns_fd;			/* input */
	__u32 buf_size;			/* input */
	__u32 buf_nr;			/* input */
};

#define INIT_NET_FD -1

#define SKB_TRACE_MAGIC	0x65617400
#define SKB_TRACE_VERSION 0x01

struct skb_trace_slot {
	__u32 magic;		/* MAGIC << 8 | version */
	__u32 sequence;		/* event number */
	__u64 time;		/* in nanoseconds */
	__u32 cpu;		/* on what cpu did it happen */
};

#endif /* _UAPIBLKTRACE_H */
