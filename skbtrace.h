#ifndef BLKTRACE_H
#define BLKTRACE_H

#include <stdio.h>
#include <limits.h>
#include <byteswap.h>
#include <endian.h>
#include <sys/types.h>

#include "skbtrace_api.h"

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)
#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))

#define SECONDS(x) 		((unsigned long long)(x) / 1000000000)
#define NANO_SECONDS(x)		((unsigned long long)(x) % 1000000000)
#define DOUBLE_TO_NANO_ULL(d)	((unsigned long long)((d) * 1000000000))

#define min(a, b)	((a) < (b) ? (a) : (b))
#define max(a, b)	((a) > (b) ? (a) : (b))

#define t_sec(t)	((t)->bytes >> 9)
#define t_kb(t)		((t)->bytes >> 10)
#define t_b(t)		((t)->bytes & 1023)

typedef __u32 u32;
typedef __u8 u8;

#ifndef SIOCSKBTRACESETUP
#define SIOCSKBTRACESETUP 0x8A00
#define SIOCSKBTRACESTART 0x8A01
#define SIOCSKBTRACESTOP 0x8A02
#define SIOCSKBTRACETEARDOWN 0x8A03
#endif

#endif
