/* Heavily borrowed from blktrace.c
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <sched.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <locale.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <dirent.h>

#include "skbtrace.h"
#include "list.h"

/*
 * You may want to increase this even more, if you are logging at a high
 * rate and see skipped/missed events
 */
#define BUF_SIZE		(512 * 1024)
#define BUF_NR			(4)

#define FILE_VBUF_SIZE		(128 * 1024)

#define DEBUGFS_TYPE		(0x64626720)

enum thread_status {
	Th_running,
	Th_leaving,
	Th_error
};

/*
 * Generic stats collected: nevents can be _roughly_ estimated by data_read
 * (discounting pdu...)
 *
 * These fields are updated w/ pdc_dr_update & pdc_nev_update below.
 */
struct pdc_stats {
	unsigned long long data_read;
	unsigned long long nevents;
};

struct netns {
	struct list_head head;
	char *name;			/* path to device special file */
	struct pdc_stats *stats;
	int control_fd, netns_fd;
	int ncpus;
	unsigned long long drops;

	/*
	 * For piped output only:
	 *
	 * Each tracer will have a tracer_netns_head that it will add new
	 * data onto. It's list is protected above (tracer_netns_head.mutex)
	 * and it will signal the processing thread using the dp_cond,
	 * dp_mutex & dp_entries variables above.
	 */
	struct tracer_netns_head *heads;

	int setup_done;	/* ioctl SIOCSKBTRACESETUP done */
	struct io_info *ios;
};

/*
 * For piped output to stdout we will have each tracer thread (one per dev)
 * tack buffers read from the relay queues on a per-device list.
 *
 * The main thread will then collect trace buffers from each of lists in turn.
 *
 * We will use a mutex to guard each of the trace_buf list. The tracers
 * can then signal the main thread using <dp_cond,dp_mutex> and
 * dp_entries. (When dp_entries is 0, and a tracer adds an entry it will
 * signal. When dp_entries is 0, the main thread will wait for that condition
 * to be signalled.)
 *
 * adb: It may be better just to have a large buffer per tracer per dev,
 * and then use it as a ring-buffer. This would certainly cut down a lot
 * of malloc/free thrashing, at the cost of more memory movements (potentially).
 */
struct trace_buf {
	struct list_head head;
	struct netns *netns;
	void *buf;
	int cpu, len;
};

struct tracer_netns_head {
	pthread_mutex_t mutex;
	struct list_head head;
	struct trace_buf *prev;
};

/*
 * Used to handle the mmap() interfaces for output file (containing traces)
 */
struct mmap_info {
	void *fs_buf;
	unsigned long long fs_size, fs_max_size, fs_off, fs_buf_len;
	unsigned long buf_size, buf_nr;
	int pagesize;
};

/*
 * Each thread doing work on a (client) side of blktrace will have one
 * of these. The ios array contains input/output information, pfds holds
 * poll() data. The volatile's provide flags to/from the main executing
 * thread.
 */
struct tracer {
	struct list_head head;
	struct io_info *ios;
	struct pollfd *pfds;
	pthread_t thread;
	int cpu, nios;
	volatile int status, is_done;
};

/*
 * This structure is (generically) used to providide information
 * for a read-to-write set of values.
 *
 * ifn & ifd represent input information
 *
 * ofn, ofd, ofp, obuf & mmap_info are used for output file (optionally).
 */
struct io_info {
	struct netns *netns;
	FILE *ofp;
	char *obuf;
	/*
	 * mmap controlled output files
	 */
	struct mmap_info mmap_info;

	/*
	 * Input/output file descriptors & names
	 */
	int ifd, ofd;
	char ifn[MAXPATHLEN + 64];
	char ofn[MAXPATHLEN + 64];
};

static char skbtrace_version[] = "0.1";

static int num_netns;
static int max_cpus;
static int ncpus;
static cpu_set_t *online_cpus;
static int pagesize;
static int kill_running_trace;
static int stop_watch;
static int piped_output;

static char *debugfs_path = "/sys/kernel/debug";
static char *output_name;
static char *output_dir;

static unsigned long buf_size = BUF_SIZE;
static unsigned long buf_nr = BUF_NR;

static FILE *pfp;

static LIST_HEAD(netnses);
static LIST_HEAD(tracers);

static volatile int done;

/*
 * tracer threads add entries, the main thread takes them off and processes
 * them. These protect the dp_entries variable.
 */
static pthread_cond_t dp_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t dp_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int dp_entries;

/*
 * These synchronize master / thread interactions.
 */
static pthread_cond_t mt_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mt_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int nthreads_running;
static volatile int nthreads_leaving;
static volatile int nthreads_error;
static volatile int tracers_run;

static int (*handle_pfds)(struct tracer *, int, int);
static int (*handle_list)(struct tracer_netns_head *, struct list_head *);

#define S_OPTS	"r:o:kw:vVb:n:D:h"
static struct option l_opts[] = {
	{
		.name = "relay",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'r'
	},
	{
		.name = "output",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'o'
	},
	{
		.name = "kill",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'k'
	},
	{
		.name = "stopwatch",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'w'
	},
	{
		.name = "version",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'v'
	},
	{
		.name = "version",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'V'
	},
	{
		.name = "buffer-size",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'b'
	},
	{
		.name = "num-sub-buffers",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'n'
	},
	{
		.name = "output-dir",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'D'
	},
	{
		.name = "help",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'h'
	},
	{
		.name = NULL,
	}
};

static char usage_str[] = "\n\n" \
        "[ -r <debugfs path>  | --relay=<debugfs path> ]\n" \
        "[ -o <file>          | --output=<file>]\n" \
        "[ -k                 | --kill]\n" \
        "[ -D <dir>           | --output-dir=<dir>\n" \
        "[ -w <time>          | --stopwatch=<time>]\n" \
        "[ -b <size>          | --buffer-size]\n" \
        "[ -n <number>        | --num-sub-buffers=<number>]\n" \
        "[ -v <version>       | --version]\n" \
        "[ -V <version>       | --version]\n" \
        "[ -h                 | --help]\n" \

	"\t-d Use specified device. May also be given last after options\n" \
	"\t-r Path to mounted debugfs, defaults to /sys/kernel/debug\n" \
	"\t-o File(s) to send output to\n" \
	"\t-k Kill tracing\n" \
	"\t-D Directory to prepend to output file names\n" \
	"\t-w Stop after defined time, in seconds\n" \
	"\t-b Sub buffer size in KiB (default 512)\n" \
	"\t-n Number of sub buffers (default 4)\n" \
	"\t-v Print program version info\n" \
	"\t-V Print program version info\n" \
	"\t-h Print this message\n\n";

static void clear_events(struct pollfd *pfd)
{
	pfd->events = 0;
	pfd->revents = 0;
}

static inline int use_tracer_netnses(void)
{
	return piped_output;
}

static inline void pdc_dr_update(struct netns *netns, int cpu, int data_read)
{
	netns->stats[cpu].data_read += data_read;
}

static inline void pdc_nev_update(struct netns *netns, int cpu, int nevents)
{
	netns->stats[cpu].nevents += nevents;
}

static void show_usage(char *prog)
{
	fprintf(stderr, "Usage: %s [options] netns...\nOptions: %s", prog, usage_str);
}

/*
 * Create a timespec 'msec' milliseconds into the future
 */
static inline void make_timespec(struct timespec *tsp, long delta_msec)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	tsp->tv_sec = now.tv_sec;
	tsp->tv_nsec = 1000L * now.tv_usec;

	tsp->tv_nsec += (delta_msec * 1000000L);
	if (tsp->tv_nsec > 1000000000L) {
		long secs = tsp->tv_nsec / 1000000000L;

		tsp->tv_sec += secs;
		tsp->tv_nsec -= (secs * 1000000000L);
	}
}

/*
 * Add a timer to ensure wait ends
 */
static void t_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	struct timespec ts;

	make_timespec(&ts, 50);
	pthread_cond_timedwait(cond, mutex, &ts);
}

static void unblock_tracers(void)
{
	pthread_mutex_lock(&mt_mutex);
	tracers_run = 1;
	pthread_cond_broadcast(&mt_cond);
	pthread_mutex_unlock(&mt_mutex);
}

static void tracer_wait_unblock(struct tracer *tp)
{
	pthread_mutex_lock(&mt_mutex);
	while (!tp->is_done && !tracers_run)
		pthread_cond_wait(&mt_cond, &mt_mutex);
	pthread_mutex_unlock(&mt_mutex);
}

static void tracer_signal_ready(struct tracer *tp,
				enum thread_status th_status,
				int status)
{
	pthread_mutex_lock(&mt_mutex);
	tp->status = status;

	if (th_status == Th_running)
		nthreads_running++;
	else if (th_status == Th_error)
		nthreads_error++;
	else
		nthreads_leaving++;

	pthread_cond_signal(&mt_cond);
	pthread_mutex_unlock(&mt_mutex);
}

static void wait_tracers_ready(int ncpus_started)
{
	pthread_mutex_lock(&mt_mutex);
	while ((nthreads_running + nthreads_error) < ncpus_started)
		t_pthread_cond_wait(&mt_cond, &mt_mutex);
	pthread_mutex_unlock(&mt_mutex);
}

static void wait_tracers_leaving(void)
{
	pthread_mutex_lock(&mt_mutex);
	while (nthreads_leaving < nthreads_running)
		t_pthread_cond_wait(&mt_cond, &mt_mutex);
	pthread_mutex_unlock(&mt_mutex);
}

static void init_mmap_info(struct mmap_info *mip)
{
	mip->buf_size = buf_size;
	mip->buf_nr = buf_nr;
	mip->pagesize = pagesize;
}

static void netns_free(struct netns *netns)
{
	if (netns->stats)
		free(netns->stats);
	if (netns->ios)
		free(netns->ios);
	if (netns->name)
		free(netns->name);
	free(netns);
}

static int lock_on_cpu(int cpu)
{
	cpu_set_t * cpu_mask;
	size_t size;

	cpu_mask = CPU_ALLOC(max_cpus);
	size = CPU_ALLOC_SIZE(max_cpus);

	CPU_ZERO_S(size, cpu_mask);
	CPU_SET_S(cpu, size, cpu_mask);
	if (sched_setaffinity(0, size, cpu_mask) < 0) {
		CPU_FREE(cpu_mask);		
		return errno;
	}

	CPU_FREE(cpu_mask);		
	return 0;
}

static int increase_limit(int resource, rlim_t increase)
{
	struct rlimit rlim;
	int save_errno = errno;

	if (!getrlimit(resource, &rlim)) {
		rlim.rlim_cur += increase;
		if (rlim.rlim_cur >= rlim.rlim_max)
			rlim.rlim_max = rlim.rlim_cur + increase;

		if (!setrlimit(resource, &rlim))
			return 1;
	}

	errno = save_errno;
	return 0;
}

static int handle_open_failure(void)
{
	if (errno == ENFILE || errno == EMFILE)
		return increase_limit(RLIMIT_NOFILE, 16);
	return 0;
}

static int handle_mem_failure(size_t length)
{
	if (errno == ENFILE)
		return handle_open_failure();
	else if (errno == ENOMEM)
		return increase_limit(RLIMIT_MEMLOCK, 2 * length);
	return 0;
}

static FILE *my_fopen(const char *path, const char *mode)
{
	FILE *fp;

	do {
		fp = fopen(path, mode);
	} while (fp == NULL && handle_open_failure());

	return fp;
}

static int my_open(const char *path, int flags)
{
	int fd;

	do {
		fd = open(path, flags);
	} while (fd < 0 && handle_open_failure());

	return fd;
}

static void *my_mmap(void *addr, size_t length, int prot, int flags, int fd,
		     off_t offset)
{
	void *new;

	do {
		new = mmap(addr, length, prot, flags, fd, offset);
	} while (new == MAP_FAILED && handle_mem_failure(length));

	return new;
}

static int my_mlock(struct tracer *tp,
		    const void *addr, size_t len)
{
	int ret, retry = 0;

	do {
		ret = mlock(addr, len);
		if ((retry >= 10) && tp && tp->is_done)
			break;
		retry++;
	} while (ret < 0 && handle_mem_failure(len));

	return ret;
}

static int setup_mmap(int fd, unsigned int maxlen,
		      struct mmap_info *mip,
		      struct tracer *tp)
{
	if (mip->fs_off + maxlen > mip->fs_buf_len) {
		unsigned long nr = max(16, mip->buf_nr);

		if (mip->fs_buf) {
			munlock(mip->fs_buf, mip->fs_buf_len);
			munmap(mip->fs_buf, mip->fs_buf_len);
			mip->fs_buf = NULL;
		}

		mip->fs_off = mip->fs_size & (mip->pagesize - 1);
		mip->fs_buf_len = (nr * mip->buf_size) - mip->fs_off;
		mip->fs_max_size += mip->fs_buf_len;

		if (ftruncate(fd, mip->fs_max_size) < 0) {
			perror("setup_mmap: ftruncate");
			return 1;
		}

		mip->fs_buf = my_mmap(NULL, mip->fs_buf_len, PROT_WRITE,
				      MAP_SHARED, fd,
				      mip->fs_size - mip->fs_off);
		if (mip->fs_buf == MAP_FAILED) {
			perror("setup_mmap: mmap");
			return 1;
		}
		if (my_mlock(tp, mip->fs_buf, mip->fs_buf_len) < 0) {
			perror("setup_mlock: mlock");
			return 1;
		}
	}

	return 0;
}

static int stop_trace(int control_fd, int netns_fd)
{
	struct skb_user_trace_setup sbts = { .netns_fd = netns_fd } ;
	/*
	 * Should be stopped, don't complain if it isn't
	 */
	ioctl(control_fd, SIOCSKBTRACESTOP, &sbts);
	return ioctl(control_fd, SIOCSKBTRACETEARDOWN, &sbts);
}

static int write_data(char *buf, int len)
{
	int ret;

rewrite:
	ret = fwrite(buf, len, 1, pfp);
	if (ferror(pfp) || ret != 1) {
		if (errno == EINTR) {
			clearerr(pfp);
			goto rewrite;
		}

		if (!piped_output || (errno != EPIPE && errno != EBADF)) {
			fprintf(stderr, "write(%d) failed: %d/%s\n",
				len, errno, strerror(errno));
		}
		goto err;
	}

	fflush(pfp);
	return 0;

err:
	clearerr(pfp);
	return 1;
}

static int setup_sbts(void)
{
	struct list_head *p;
	int ret = 0;

	__list_for_each(p, &netnses) {
		struct skb_user_trace_setup sbts;
		struct netns *netns = list_entry(p, struct netns, head);

		memset(&sbts, 0, sizeof(sbts));
		sbts.buf_size = buf_size;
		sbts.buf_nr = buf_nr;
		sbts.netns_fd = netns->netns_fd;
		strcpy(sbts.name, netns->name);

		if (ioctl(netns->control_fd, SIOCSKBTRACESETUP, &sbts) >= 0) {
			netns->ncpus = max_cpus;
			netns->setup_done = 1;
			if (netns->stats)
				free(netns->stats);
			netns->stats = calloc(netns->ncpus, sizeof(*netns->stats));
			memset(netns->stats, 0, netns->ncpus * sizeof(*netns->stats));
		} else {
			fprintf(stderr, "SIOCSKBTRACESETUP(2) %s failed: %d/%s\n",
				netns->name, errno, strerror(errno));
			ret++;
		}
	}

	return ret;
}

static void start_trace(void)
{
	struct list_head *p;

	__list_for_each(p, &netnses) {
		struct netns *netns = list_entry(p, struct netns, head);
		struct skb_user_trace_setup sbts = { .netns_fd = netns->netns_fd } ;

		if (ioctl(netns->control_fd, SIOCSKBTRACESTART, &sbts) < 0) {
			fprintf(stderr, "SIOCSKBTRACESTART %s failed: %d/%s\n",
				netns->name, errno, strerror(errno));
		}
	}
}

static inline struct trace_buf *alloc_trace_buf(int cpu, int bufsize)
{
	struct trace_buf *tbp;

	tbp = malloc(sizeof(*tbp) + bufsize);
	INIT_LIST_HEAD(&tbp->head);
	tbp->len = 0;
	tbp->buf = (void *)(tbp + 1);
	tbp->cpu = cpu;
	tbp->netns = NULL;	/* Will be set when tbp is added */

	return tbp;
}

static void free_tracer_heads(struct netns *netns)
{
	int cpu;
	struct tracer_netns_head *hd;

	for (cpu = 0, hd = netns->heads; cpu < max_cpus; cpu++, hd++) {
		if (hd->prev)
			free(hd->prev);

		pthread_mutex_destroy(&hd->mutex);
	}
	free(netns->heads);
}

static int setup_tracer_netnses(void)
{
	struct list_head *p;

	__list_for_each(p, &netnses) {
		int cpu;
		struct tracer_netns_head *hd;
		struct netns *netns = list_entry(p, struct netns, head);

		netns->heads = calloc(max_cpus, sizeof(struct tracer_netns_head));
		for (cpu = 0, hd = netns->heads; cpu < max_cpus; cpu++, hd++) {
			INIT_LIST_HEAD(&hd->head);
			pthread_mutex_init(&hd->mutex, NULL);
			hd->prev = NULL;
		}
	}

	return 0;
}

static inline void add_trace_buf(struct netns *netns, int cpu,
						struct trace_buf **tbpp)
{
	struct trace_buf *tbp = *tbpp;
	struct tracer_netns_head *hd = &netns->heads[cpu];

	tbp->netns = netns;

	pthread_mutex_lock(&hd->mutex);
	list_add_tail(&tbp->head, &hd->head);
	pthread_mutex_unlock(&hd->mutex);

	*tbpp = alloc_trace_buf(cpu, buf_size);
}

static inline void incr_entries(int entries_handled)
{
	pthread_mutex_lock(&dp_mutex);
	if (dp_entries == 0)
		pthread_cond_signal(&dp_cond);
	dp_entries += entries_handled;
	pthread_mutex_unlock(&dp_mutex);
}

static void decr_entries(int handled)
{
	pthread_mutex_lock(&dp_mutex);
	dp_entries -= handled;
	pthread_mutex_unlock(&dp_mutex);
}

static int wait_empty_entries(void)
{
	pthread_mutex_lock(&dp_mutex);
	while (!done && dp_entries == 0)
		t_pthread_cond_wait(&dp_cond, &dp_mutex);
	pthread_mutex_unlock(&dp_mutex);

	return !done;
}

#ifndef NETNS_RUN_DIR
#define NETNS_RUN_DIR "/var/run/netns"
#endif

int open_netns(const char *name)
{
        char pathbuf[PATH_MAX];
        const char *path, *ptr;

        path = name;
        ptr = strchr(name, '/');
        if (!ptr) {
                snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
                        NETNS_RUN_DIR, name );
                path = pathbuf;
        }
        return open(path, O_RDONLY);
}

static int add_netns(char *netns_name)
{
	int fd;
	struct netns *netns;
	struct list_head *p;

	if (netns_name) {
		fd = open_netns(netns_name);
		if (fd < 0) {
			fprintf(stderr, "Invalid netns name %s specified: %d/%s\n",
				netns_name, errno, strerror(errno));
			return 1;
		}
	} else {
		fd = INIT_NET_FD;
		netns_name = "init_net";
	}

	__list_for_each(p, &netnses) {
	       struct netns *tmp = list_entry(p, struct netns, head);
	       if (!strcmp(tmp->name, netns_name))
		        return 0;
	}

	netns = malloc(sizeof(*netns));
	memset(netns, 0, sizeof(*netns));
	netns->name = strdup(netns_name);
	netns->netns_fd = fd;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Can not create a socket: %d/%s\n",
			errno, strerror(errno));
		free(netns->name);
		close(netns->netns_fd);
		free(netns);
		return 1;
	}
	netns->control_fd = fd;
	num_netns++;
	list_add_tail(&netns->head, &netnses);

	return 0;
}

static void rel_netnses(void)
{
	struct list_head *p, *q;

	list_for_each_safe(p, q, &netnses) {
		struct netns *netns = list_entry(p, struct netns, head);

		list_del(&netns->head);
		if (netns->setup_done)
			stop_trace(netns->control_fd, netns->netns_fd);
		close(netns->netns_fd);
		close(netns->control_fd);

		if (netns->heads)
			free_tracer_heads(netns);

		netns_free(netns);
		num_netns--;
	}
}

/*
 * Tack 'tbp's buf onto the tail of 'prev's buf
 */
static struct trace_buf *tb_combine(struct trace_buf *prev,
				    struct trace_buf *tbp)
{
	unsigned long tot_len;

	tot_len = prev->len + tbp->len;
	if (tot_len > buf_size) {
		/*
		 * tbp->head isn't connected (it was 'prev'
		 * so it had been taken off of the list
		 * before). Therefore, we can realloc
		 * the whole structures, as the other fields
		 * are "static".
		 */
		prev = realloc(prev, sizeof(*prev) + tot_len);
		prev->buf = (void *)(prev + 1);
	}

	memcpy(prev->buf + prev->len, tbp->buf, tbp->len);
	prev->len = tot_len;

	free(tbp);
	return prev;
}

static int handle_list_file(struct tracer_netns_head *hd,
			    struct list_head *list)
{
	int off, t_len, nevents;
	struct skb_trace_slot *t;
	struct list_head *p, *q;
	int entries_handled = 0;
	struct trace_buf *tbp, *prev;

	prev = hd->prev;
	list_for_each_safe(p, q, list) {
		tbp = list_entry(p, struct trace_buf, head);
		list_del(&tbp->head);
		entries_handled++;

		/*
		 * If there was some leftover before, tack this new
		 * entry onto the tail of the previous one.
		 */
		if (prev)
			tbp = tb_combine(prev, tbp);

		/*
		 * See how many whole traces there are - send them
		 * all out in one go.
		 */
		off = 0;
		nevents = 0;
		while (off + (int)sizeof(*t) <= tbp->len) {
			t = (struct skb_trace_slot*)(tbp->buf + off);
			t_len = sizeof(*t);
			if (off + t_len > tbp->len)
				break;

			off += t_len;
			nevents++;
		}
		if (nevents)
			pdc_nev_update(tbp->netns, tbp->cpu, nevents);

		/*
		 * Write any full set of traces, any remaining data is kept
		 * for the next pass.
		 */
		if (off) {
			if (write_data(tbp->buf, off) || off == tbp->len) {
				free(tbp);
				prev = NULL;
			}
			else {
				/*
				 * Move valid data to beginning of buffer
				 */
				tbp->len -= off;
				memmove(tbp->buf, tbp->buf + off, tbp->len);
				prev = tbp;
			}
		} else
			prev = tbp;
	}
	hd->prev = prev;

	return entries_handled;
}

static void __process_trace_bufs(void)
{
	int cpu;
	struct list_head *p;
	struct list_head list;
	int handled = 0;

	__list_for_each(p, &netnses) {
		struct netns *netns = list_entry(p, struct netns, head);
		struct tracer_netns_head *hd = netns->heads;

		for (cpu = 0; cpu < max_cpus; cpu++, hd++) {
			pthread_mutex_lock(&hd->mutex);
			if (list_empty(&hd->head)) {
				pthread_mutex_unlock(&hd->mutex);
				continue;
			}

			list_replace_init(&hd->head, &list);
			pthread_mutex_unlock(&hd->mutex);

			handled += handle_list(hd, &list);
		}
	}

	if (handled)
		decr_entries(handled);
}

static void process_trace_bufs(void)
{
	while (wait_empty_entries())
		__process_trace_bufs();
}

static void clean_trace_bufs(void)
{
	/*
	 * No mutex needed here: we're only reading from the lists,
	 * tracers are done
	 */
	while (dp_entries)
		__process_trace_bufs();
}

static inline void read_err(int cpu, char *ifn)
{
	if (errno != EAGAIN)
		fprintf(stderr, "Thread %d failed read of %s: %d/%s\n",
			cpu, ifn, errno, strerror(errno));
}

static int fill_ofname(char *dst, int dstlen, char *subdir, char *netns_name,
		       int cpu)
{
	int len;
	struct stat sb;

	if (output_dir)
		len = snprintf(dst, dstlen, "%s/", output_dir);
	else
		len = snprintf(dst, dstlen, "./");

	if (subdir)
		len += snprintf(dst + len, dstlen - len, "%s", subdir);

	if (stat(dst, &sb) < 0) {
		if (errno != ENOENT) {
			fprintf(stderr,
				"Destination dir %s stat failed: %d/%s\n",
				dst, errno, strerror(errno));
			return 1;
		}
		/*
		 * There is no synchronization between multiple threads
		 * trying to create the directory at once.  It's harmless
		 * to let them try, so just detect the problem and move on.
		 */
		if (mkdir(dst, 0755) < 0 && errno != EEXIST) {
			fprintf(stderr,
				"Destination dir %s can't be made: %d/%s\n",
				dst, errno, strerror(errno));
			return 1;
		}
	}

	if (output_name)
		snprintf(dst + len, dstlen - len, "%s.skbtrace.%d",
			 output_name, cpu);
	else
		snprintf(dst + len, dstlen - len, "%s.skbtrace.%d",
			 netns_name, cpu);

	return 0;
}

static int set_vbuf(struct io_info *iop, int mode, size_t size)
{
	iop->obuf = malloc(size);
	if (setvbuf(iop->ofp, iop->obuf, mode, size) < 0) {
		fprintf(stderr, "setvbuf(%s, %d) failed: %d/%s\n",
			iop->netns->name, (int)size, errno,
			strerror(errno));
		free(iop->obuf);
		return 1;
	}

	return 0;
}

static int iop_open(struct io_info *iop, int cpu)
{
	char hostdir[MAXPATHLEN + 64];

	iop->ofd = -1;
	hostdir[0] = 0;

	if (fill_ofname(iop->ofn, sizeof(iop->ofn), hostdir,
			iop->netns->name, cpu))
		return 1;

	iop->ofp = my_fopen(iop->ofn, "w+");
	if (iop->ofp == NULL) {
		fprintf(stderr, "Open output file %s failed: %d/%s\n",
			iop->ofn, errno, strerror(errno));
		return 1;
	}

	if (set_vbuf(iop, _IOLBF, FILE_VBUF_SIZE)) {
		fprintf(stderr, "set_vbuf for file %s failed: %d/%s\n",
			iop->ofn, errno, strerror(errno));
		fclose(iop->ofp);
		return 1;
	}

	iop->ofd = fileno(iop->ofp);
	return 0;
}

static void close_iop(struct io_info *iop)
{
	struct mmap_info *mip = &iop->mmap_info;

	if (mip->fs_buf)
		munmap(mip->fs_buf, mip->fs_buf_len);

	if (!piped_output) {
		if (ftruncate(fileno(iop->ofp), mip->fs_size) < 0) {
			fprintf(stderr,
				"Ignoring err: ftruncate(%s): %d/%s\n",
				iop->ofn, errno, strerror(errno));
		}
	}

	if (iop->ofp)
		fclose(iop->ofp);
	if (iop->obuf)
		free(iop->obuf);
}

static void close_ios(struct tracer *tp)
{
	while (tp->nios > 0) {
		struct io_info *iop = &tp->ios[--tp->nios];

		if (iop->ifd >= 0)
			close(iop->ifd);

		if (iop->ofp)
			close_iop(iop);
		else if (iop->ofd >= 0) {
		}
	}

	free(tp->ios);
	free(tp->pfds);
}

static int open_ios(struct tracer *tp)
{
	struct pollfd *pfd;
	struct io_info *iop;
	struct list_head *p;

	tp->ios = calloc(num_netns, sizeof(struct io_info));
	memset(tp->ios, 0, num_netns * sizeof(struct io_info));

	tp->pfds = calloc(num_netns, sizeof(struct pollfd));
	memset(tp->pfds, 0, num_netns * sizeof(struct pollfd));

	tp->nios = 0;
	iop = tp->ios;
	pfd = tp->pfds;
	__list_for_each(p, &netnses) {
		struct netns *netns = list_entry(p, struct netns, head);

		iop->netns = netns;
		iop->ofd = -1;
		snprintf(iop->ifn, sizeof(iop->ifn), "%s/skbuff/%s/trace%d",
			debugfs_path, netns->name, tp->cpu);

		iop->ifd = my_open(iop->ifn, O_RDONLY | O_NONBLOCK);
		if (iop->ifd < 0) {
			fprintf(stderr, "Thread %d failed open %s: %d/%s\n",
				tp->cpu, iop->ifn, errno, strerror(errno));
			return 1;
		}

		init_mmap_info(&iop->mmap_info);

		pfd->fd = iop->ifd;
		pfd->events = POLLIN;

		if (!piped_output && iop_open(iop, tp->cpu))
			goto err;
		pfd++;
		iop++;
		tp->nios++;
	}

	return 0;

err:
	close(iop->ifd);	/* tp->nios _not_ bumped */
	close_ios(tp);
	return 1;
}

static int handle_pfds_file(struct tracer *tp, int nevs, int force_read)
{
	struct mmap_info *mip;
	int i, ret, nentries = 0;
	struct pollfd *pfd = tp->pfds;
	struct io_info *iop = tp->ios;

	for (i = 0; nevs > 0 && i < num_netns; i++, pfd++, iop++) {
		if (pfd->revents & POLLIN || force_read) {
			mip = &iop->mmap_info;

			ret = setup_mmap(iop->ofd, buf_size, mip, tp);
			if (ret < 0) {
				pfd->events = 0;
				break;
			}

			ret = read(iop->ifd, mip->fs_buf + mip->fs_off,
				   buf_size);
			if (ret > 0) {
				pdc_dr_update(iop->netns, tp->cpu, ret);
				mip->fs_size += ret;
				mip->fs_off += ret;
				nentries++;
			} else if (ret == 0) {
				/*
				 * Short reads after we're done stop us
				 * from trying reads.
				 */
				if (tp->is_done)
					clear_events(pfd);
			} else {
				read_err(tp->cpu, iop->ifn);
				if (errno != EAGAIN || tp->is_done)
					clear_events(pfd);
			}
			nevs--;
		}
	}

	return nentries;
}

static int handle_pfds_entries(struct tracer *tp, int nevs, int force_read)
{
	int i, nentries = 0;
	struct trace_buf *tbp;
	struct pollfd *pfd = tp->pfds;
	struct io_info *iop = tp->ios;

	tbp = alloc_trace_buf(tp->cpu, buf_size);
	for (i = 0; i < num_netns; i++, pfd++, iop++) {
		if (pfd->revents & POLLIN || force_read) {
			tbp->len = read(iop->ifd, tbp->buf, buf_size);
			if (tbp->len > 0) {
				pdc_dr_update(iop->netns, tp->cpu, tbp->len);
				add_trace_buf(iop->netns, tp->cpu, &tbp);
				nentries++;
			} else if (tbp->len == 0) {
				/*
				 * Short reads after we're done stop us
				 * from trying reads.
				 */
				if (tp->is_done)
					clear_events(pfd);
			} else {
				read_err(tp->cpu, iop->ifn);
				if (errno != EAGAIN || tp->is_done)
					clear_events(pfd);
			}
			if (!piped_output && --nevs == 0)
				break;
		}
	}
	free(tbp);

	if (nentries)
		incr_entries(nentries);

	return nentries;
}

static void *thread_main(void *arg)
{
	int ret, ndone, to_val;
	struct tracer *tp = arg;

	ret = lock_on_cpu(tp->cpu);
	if (ret)
		goto err;

	ret = open_ios(tp);
	if (ret)
		goto err;

	if (piped_output)
		to_val = 50;		/* Frequent partial handles */
	else
		to_val = 500;		/* 1/2 second intervals */


	tracer_signal_ready(tp, Th_running, 0);
	tracer_wait_unblock(tp);

	while (!tp->is_done) {
		ndone = poll(tp->pfds, num_netns, to_val);
		if (ndone || piped_output)
			(void)handle_pfds(tp, ndone, piped_output);
		else if (ndone < 0 && errno != EINTR)
			fprintf(stderr, "Thread %d poll failed: %d/%s\n",
				tp->cpu, errno, strerror(errno));
	}

	/*
	 * Trace is stopped, pull data until we get a short read
	 */
	while (handle_pfds(tp, num_netns, 1) > 0)
		;

	close_ios(tp);
	tracer_signal_ready(tp, Th_leaving, 0);
	return NULL;

err:
	tracer_signal_ready(tp, Th_error, ret);
	return NULL;
}

static int start_tracer(int cpu)
{
	struct tracer *tp;

	tp = malloc(sizeof(*tp));
	memset(tp, 0, sizeof(*tp));

	INIT_LIST_HEAD(&tp->head);
	tp->status = 0;
	tp->cpu = cpu;

	if (pthread_create(&tp->thread, NULL, thread_main, tp)) {
		fprintf(stderr, "FAILED to start thread on CPU %d: %d/%s\n",
			cpu, errno, strerror(errno));
		free(tp);
		return 1;
	}

	list_add_tail(&tp->head, &tracers);
	return 0;
}

static int create_output_files(int cpu)
{
	char fname[MAXPATHLEN + 64];
	struct list_head *p;
	FILE *f;

	__list_for_each(p, &netnses) {
		struct netns *netns = list_entry(p, struct netns, head);

		if (fill_ofname(fname, sizeof(fname), NULL, netns->name,
				cpu))
			return 1;
		f = my_fopen(fname, "w+");
		if (!f)
			return 1;
		fclose(f);
	}
	return 0;
}

static void start_tracers(void)
{
	int cpu, started = 0;
	struct list_head *p;
	size_t alloc_size = CPU_ALLOC_SIZE(max_cpus);

	for (cpu = 0; cpu < max_cpus; cpu++) {
		if (!CPU_ISSET_S(cpu, alloc_size, online_cpus)) {
			/*
			 * Create fake empty output files so that other tools
			 * like blkparse don't have to bother with sparse CPU
			 * number space.
			 */
			if (create_output_files(cpu))
				break;
			continue;
		}
		if (start_tracer(cpu))
			break;
		started++;
	}

	wait_tracers_ready(started);

	__list_for_each(p, &tracers) {
		struct tracer *tp = list_entry(p, struct tracer, head);
		if (tp->status)
			fprintf(stderr,
				"FAILED to start thread on CPU %d: %d/%s\n",
				tp->cpu, tp->status, strerror(tp->status));
	}
}

static void stop_tracers(void)
{
	struct list_head *p;

	/*
	 * Stop the tracing - makes the tracer threads clean up quicker.
	 */
	__list_for_each(p, &netnses) {
		struct netns *netns = list_entry(p, struct netns, head);
		(void)ioctl(netns->control_fd, SIOCSKBTRACESTOP);
	}

	/*
	 * Tell each tracer to quit
	 */
	__list_for_each(p, &tracers) {
		struct tracer *tp = list_entry(p, struct tracer, head);
		tp->is_done = 1;
	}
	pthread_cond_broadcast(&mt_cond);
}

static void del_tracers(void)
{
	struct list_head *p, *q;

	list_for_each_safe(p, q, &tracers) {
		struct tracer *tp = list_entry(p, struct tracer, head);

		list_del(&tp->head);
		free(tp);
	}
}

static void wait_tracers(void)
{
	struct list_head *p;

	if (use_tracer_netnses())
		process_trace_bufs();

	wait_tracers_leaving();

	__list_for_each(p, &tracers) {
		int ret;
		struct tracer *tp = list_entry(p, struct tracer, head);

		ret = pthread_join(tp->thread, NULL);
		if (ret)
			fprintf(stderr, "Thread join %d failed %d\n",
				tp->cpu, ret);
	}

	if (use_tracer_netnses())
		clean_trace_bufs();
}

static void exit_tracing(void)
{
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGALRM, SIG_IGN);

	stop_tracers();
	wait_tracers();
	del_tracers();
	rel_netnses();
}

static void handle_sigint(__attribute__((__unused__)) int sig)
{
	done = 1;
	stop_tracers();
}

static void show_stats(struct list_head *netnses)
{
	FILE *ofp;
	struct list_head *p;
	unsigned long long nevents, data_read;
	unsigned long long total_drops = 0;
	unsigned long long total_events = 0;

	if (piped_output)
		ofp = my_fopen("/dev/null", "w");
	else
		ofp = stdout;

	__list_for_each(p, netnses) {
		int cpu;
		struct pdc_stats *sp;
		struct netns *netns = list_entry(p, struct netns, head);

		data_read = 0;
		nevents = 0;

		fprintf(ofp, "=== %s ===\n", netns->name);
		for (cpu = 0, sp = netns->stats; cpu < netns->ncpus; cpu++, sp++) {
			/*
			 * Estimate events if not known...
			 */
			if (sp->nevents == 0) {
				sp->nevents = sp->data_read /
						sizeof(struct skb_trace_slot);
			}

			fprintf(ofp,
				"  CPU%3d: %20llu events, %8llu KiB data\n",
				cpu, sp->nevents, (sp->data_read + 1023) >> 10);

			data_read += sp->data_read;
			nevents += sp->nevents;
		}

		fprintf(ofp, "  Total:  %20llu events (dropped %llu),"
			     " %8llu KiB data\n", nevents,
			     netns->drops, (data_read + 1024) >> 10);

		total_drops += netns->drops;
		total_events += (nevents + netns->drops);
	}

	fflush(ofp);
	if (piped_output)
		fclose(ofp);

	if (total_drops) {
		double drops_ratio = 1.0;

		if (total_events)
			drops_ratio = (double)total_drops/(double)total_events;

		fprintf(stderr, "\nYou have %llu (%5.1lf%%) dropped events\n"
				"Consider using a larger buffer size (-b) "
				"and/or more buffers (-n)\n",
			total_drops, 100.0 * drops_ratio);
	}
}

static int handle_args(int argc, char *argv[])
{
	int c;
	struct statfs st;

	while ((c = getopt_long(argc, argv, S_OPTS, l_opts, NULL)) >= 0) {
		switch (c) {
		case 'r':
			debugfs_path = optarg;
			break;

		case 'o':
			output_name = optarg;
			break;
		case 'k':
			kill_running_trace = 1;
			break;
		case 'w':
			stop_watch = atoi(optarg);
			if (stop_watch <= 0) {
				fprintf(stderr,
					"Invalid stopwatch value (%d secs)\n",
					stop_watch);
				return 1;
			}
			break;
		case 'V':
		case 'v':
			printf("%s version %s\n", argv[0], skbtrace_version);
			exit(0);
			/*NOTREACHED*/
		case 'b':
			buf_size = strtoul(optarg, NULL, 10);
			if (buf_size <= 0 || buf_size > 16*1024) {
				fprintf(stderr, "Invalid buffer size (%lu)\n",
					buf_size);
				return 1;
			}
			buf_size <<= 10;
			break;
		case 'n':
			buf_nr = strtoul(optarg, NULL, 10);
			if (buf_nr <= 0) {
				fprintf(stderr,
					"Invalid buffer nr (%lu)\n", buf_nr);
				return 1;
			}
			break;
		case 'D':
			output_dir = optarg;
			break;
		case 'h':
		default:
			show_usage(argv[0]);
			exit(1);
			/*NOTREACHED*/
		}
	}

	if (optind == argc) {
		if (add_netns(NULL) != 0)
			return 1;
	} else {
		while (optind < argc)
			if (add_netns(argv[optind++]) != 0)
				return 1;
	}

	if (num_netns == 0) {
		show_usage(argv[0]);
		return 1;
	}

	if (statfs(debugfs_path, &st) < 0) {
		fprintf(stderr, "Invalid debug path %s: %d/%s\n",
			debugfs_path, errno, strerror(errno));
		return 1;
	}

	if (st.f_type != (long)DEBUGFS_TYPE) {
		fprintf(stderr, "Debugfs is not mounted at %s\n", debugfs_path);
		return 1;
	}

	/*
	 * Set up for appropriate PFD handler based upon output name.
	 */
	if (output_name && (strcmp(output_name, "-") == 0)) {
		piped_output = 1;
		handle_pfds = handle_pfds_entries;
		pfp = stdout;
		if (setvbuf(pfp, NULL, _IONBF, 0)) {
			perror("setvbuf stdout");
			return 1;
		}
	} else
		handle_pfds = handle_pfds_file;
	return 0;
}

static int run_tracers(void)
{
	atexit(exit_tracing);
	if (setup_sbts())
		return 1;

	if (use_tracer_netnses()) {
		if (setup_tracer_netnses())
			return 1;

		if (piped_output)
			handle_list = handle_list_file;
	}

	start_tracers();
	if (nthreads_running == ncpus) {
		unblock_tracers();
		start_trace();
		if (stop_watch)
			alarm(stop_watch);
	} else
		stop_tracers();

	wait_tracers();
	if (nthreads_running == ncpus)
		show_stats(&netnses);
	del_tracers();

	return 0;
}

static cpu_set_t *get_online_cpus(void)
{
	FILE *cpus;
	cpu_set_t *set;
	size_t alloc_size;
	int cpuid, prevcpuid = -1;
	char nextch;
	int n, ncpu, curcpu = 0;
	int *cpu_nums;

	ncpu = sysconf(_SC_NPROCESSORS_CONF);
	if (ncpu < 0)
		return NULL;

	cpu_nums = malloc(sizeof(int)*ncpu);
	if (!cpu_nums) {
		errno = ENOMEM;
		return NULL;
	}

	/*
	 * There is no way to easily get maximum CPU number. So we have to
	 * parse the file first to find it out and then create appropriate
	 * cpuset
	 */
	cpus = my_fopen("/sys/devices/system/cpu/online", "r");
	for (;;) {
		n = fscanf(cpus, "%d%c", &cpuid, &nextch);
		if (n <= 0)
			break;
		if (n == 2 && nextch == '-') {
			prevcpuid = cpuid;
			continue;
		}
		if (prevcpuid == -1)
			prevcpuid = cpuid;
		while (prevcpuid <= cpuid) {
			/* More CPUs listed than configured? */
			if (curcpu >= ncpu) {
				errno = EINVAL;
				return NULL;
			}
			cpu_nums[curcpu++] = prevcpuid++;
		}
		prevcpuid = -1;
	}
	fclose(cpus);

	ncpu = curcpu;
	max_cpus = cpu_nums[ncpu - 1] + 1;

	/* Now that we have maximum cpu number, create a cpuset */
	set = CPU_ALLOC(max_cpus);
	if (!set) {
		errno = ENOMEM;
		return NULL;
	}
	alloc_size = CPU_ALLOC_SIZE(max_cpus);
	CPU_ZERO_S(alloc_size, set);

	for (curcpu = 0; curcpu < ncpu; curcpu++)
		CPU_SET_S(cpu_nums[curcpu], alloc_size, set);

	free(cpu_nums);

	return set;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	setlocale(LC_NUMERIC, "en_US");
	pagesize = getpagesize();
	online_cpus = get_online_cpus();
	if (!online_cpus) {
		fprintf(stderr, "cannot get online cpus %d/%s\n",
			errno, strerror(errno));
		ret = 1;
		goto out;
	} else if (handle_args(argc, argv)) {
		ret = 1;
		goto out;
	}

	ncpus = CPU_COUNT_S(CPU_ALLOC_SIZE(max_cpus), online_cpus);
	if (num_netns > 1 && output_name && strcmp(output_name, "-") != 0) {
		fprintf(stderr, "-o not supported with multiple devices\n");
		ret = 1;
		goto out;
	}

	signal(SIGINT, handle_sigint);
	signal(SIGHUP, handle_sigint);
	signal(SIGTERM, handle_sigint);
	signal(SIGALRM, handle_sigint);
	signal(SIGPIPE, SIG_IGN);

	if (kill_running_trace) {
		struct netns *netns;
		struct list_head *p;

		__list_for_each(p, &netnses) {
			netns = list_entry(p, struct netns, head);
			if (stop_trace(netns->control_fd, netns->netns_fd)) {
				fprintf(stderr,
					"SIOCSKBTRACETEARDOWN %s failed: %d/%s\n",
					netns->name, errno, strerror(errno));
			}
		}
	} else
		ret = run_tracers();

out:
	if (pfp)
		fclose(pfp);
	rel_netnses();
	return ret;
}
