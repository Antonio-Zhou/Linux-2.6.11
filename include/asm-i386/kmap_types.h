#ifndef _ASM_KMAP_TYPES_H
#define _ASM_KMAP_TYPES_H

#include <linux/config.h>

#ifdef CONFIG_DEBUG_HIGHMEM
# define D(n) __KM_FENCE_##n ,
#else
# define D(n)
#endif

/*
*	高端地址映射的窗口集合
*	内核确保同一窗口永不会被两个不同的内核控制路径同时使用,
*	因此,结构中的每个符号只能由一种内核成分使用,并以该成分命名
*/
enum km_type {
D(0)	KM_BOUNCE_READ,	/*窗口的线性地址,都是固定的线性地址的一个下标*/
D(1)	KM_SKB_SUNRPC_DATA,
D(2)	KM_SKB_DATA_SOFTIRQ,
D(3)	KM_USER0,
D(4)	KM_USER1,
D(5)	KM_BIO_SRC_IRQ,
D(6)	KM_BIO_DST_IRQ,
D(7)	KM_PTE0,
D(8)	KM_PTE1,
D(9)	KM_IRQ0,
D(10)	KM_IRQ1,
D(11)	KM_SOFTIRQ0,
D(12)	KM_SOFTIRQ1,
D(13)	KM_TYPE_NR		/*并不表示一个线性地址,但由每个CPU用来产生不同的可用窗口数*/
};

#undef D

#endif
