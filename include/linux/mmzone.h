#ifndef _LINUX_MMZONE_H
#define _LINUX_MMZONE_H

#ifdef __KERNEL__
#ifndef __ASSEMBLY__

#include <linux/config.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <linux/numa.h>
#include <asm/atomic.h>

/* Free memory management - zoned buddy allocator.  */
#ifndef CONFIG_FORCE_MAX_ZONEORDER
#define MAX_ORDER 11
#else
#define MAX_ORDER CONFIG_FORCE_MAX_ZONEORDER
#endif

struct free_area {
	/*
	*	双向循环链表的头,
	*	该链表包含每个空闲页框块(大小为2^k)的起始页框的页框内描述符
	*/
	struct list_head	free_list;
	/*指定了大小为2^k的空闲块的个数*/
	unsigned long		nr_free;
};

struct pglist_data;

/*
 * zone->lock and zone->lru_lock are two of the hottest locks in the kernel.
 * So add a wild amount of padding here to ensure that they fall into separate
 * cachelines.  There are very few zone structures in the machine, so space
 * consumption is not a concern here.
 */
#if defined(CONFIG_SMP)
struct zone_padding {
	char x[0];
} ____cacheline_maxaligned_in_smp;
#define ZONE_PADDING(name)	struct zone_padding name;
#else
#define ZONE_PADDING(name)
#endif

struct per_cpu_pages {
	int count;		/* number of pages in the list */
	int low;		/* low watermark, refill needed */
	int high;		/* high watermark, emptying needed */
	int batch;		/* chunk size for buddy add/remove */
	struct list_head list;	/* the list of pages */
};

struct per_cpu_pageset {
	struct per_cpu_pages pcp[2];	/* 0: hot.  1: cold */
#ifdef CONFIG_NUMA
	unsigned long numa_hit;		/* allocated in intended node */
	unsigned long numa_miss;	/* allocated in non intended node */
	unsigned long numa_foreign;	/* was intended here, hit elsewhere */
	unsigned long interleave_hit; 	/* interleaver prefered this zone */
	unsigned long local_node;	/* allocation from local node */
	unsigned long other_node;	/* allocation from other node */
#endif
} ____cacheline_aligned_in_smp;

/*包含低于16MB的内存页框，可以由老式基于ISA的设备通过DMA使用*/
#define ZONE_DMA		0
/*
*	包含高于16MB且低于896MB的内存页框。
*	通过ZONE_DMA和ZONE_NORMAL把它们线性地址映射到线性地址空间的第4个GB
*/
#define ZONE_NORMAL		1
/*
*	包含从896MB开始高于896MB的内存页框。
*	包含的页不能由内存直接访问到，尽管它们也线性的映射到了线性地址空间的第4个GB
*/
#define ZONE_HIGHMEM		2

#define MAX_NR_ZONES		3	/* Sync this with ZONES_SHIFT */
#define ZONES_SHIFT		2	/* ceil(log2(MAX_NR_ZONES)) */


/*
 * When a memory allocation must conform to specific limitations (such
 * as being suitable for DMA) the caller will pass in hints to the
 * allocator in the gfp_mask, in the zone modifier bits.  These bits
 * are used to select a priority ordered list of memory zones which
 * match the requested limits.  GFP_ZONEMASK defines which bits within
 * the gfp_mask should be considered as zone modifiers.  Each valid
 * combination of the zone modifier bits has a corresponding list
 * of zones (in node_zonelists).  Thus for two zone modifiers there
 * will be a maximum of 4 (2 ** 2) zonelists, for 3 modifiers there will
 * be 8 (2 ** 3) zonelists.  GFP_ZONETYPES defines the number of possible
 * combinations of zone modifiers in "zone modifier space".
 */
#define GFP_ZONEMASK	0x03
/*
 * As an optimisation any zone modifier bits which are only valid when
 * no other zone modifier bits are set (loners) should be placed in
 * the highest order bits of this field.  This allows us to reduce the
 * extent of the zonelists thus saving space.  For example in the case
 * of three zone modifier bits, we could require up to eight zonelists.
 * If the left most zone modifier is a "loner" then the highest valid
 * zonelist would be four allowing us to allocate only five zonelists.
 * Use the first form when the left most bit is not a "loner", otherwise
 * use the second.
 */
/* #define GFP_ZONETYPES	(GFP_ZONEMASK + 1) */		/* Non-loner */
#define GFP_ZONETYPES	((GFP_ZONEMASK + 1) / 2 + 1)		/* Loner */

/*
 * On machines where it is needed (eg PCs) we divide physical memory
 * into multiple physical zones. On a PC we have 3 zones:
 *
 * ZONE_DMA	  < 16 MB	ISA DMA capable memory
 * ZONE_NORMAL	16-896 MB	direct mapped by the kernel
 * ZONE_HIGHMEM	 > 896 MB	only page cache and user processes
 */

struct zone {
	/* Fields commonly accessed by the page allocator */
	unsigned long		free_pages;
	unsigned long		pages_min, pages_low, pages_high;
	/*
	 * We don't know if the memory that we're going to allocate will be freeable
	 * or/and it will be released eventually, so to avoid totally wasting several
	 * GB of ram we must reserve some of the lower zone memory (otherwise we risk
	 * to run OOM on the lower zones despite there's tons of freeable ram
	 * on the higher zones). This array is recalculated at runtime if the
	 * sysctl_lowmem_reserve_ratio sysctl changes.
	 */
	unsigned long		lowmem_reserve[MAX_NR_ZONES];

	struct per_cpu_pageset	pageset[NR_CPUS];

	/*
	 * free areas of different sizes
	 */
	spinlock_t		lock;
	struct free_area	free_area[MAX_ORDER];


	ZONE_PADDING(_pad1_)

	/* Fields commonly accessed by the page reclaim scanner */
	spinlock_t		lru_lock;	
	struct list_head	active_list;
	struct list_head	inactive_list;
	unsigned long		nr_scan_active;
	unsigned long		nr_scan_inactive;
	unsigned long		nr_active;
	unsigned long		nr_inactive;
	unsigned long		pages_scanned;	   /* since last reclaim */
	int			all_unreclaimable; /* All pages pinned */

	/*
	 * prev_priority holds the scanning priority for this zone.  It is
	 * defined as the scanning priority at which we achieved our reclaim
	 * target at the previous try_to_free_pages() or balance_pgdat()
	 * invokation.
	 *
	 * We use prev_priority as a measure of how much stress page reclaim is
	 * under - it drives the swappiness decision: whether to unmap mapped
	 * pages.
	 *
	 * temp_priority is used to remember the scanning priority at which
	 * this zone was successfully refilled to free_pages == pages_high.
	 *
	 * Access to both these fields is quite racy even on uniprocessor.  But
	 * it is expected to average out OK.
	 */
	int temp_priority;
	int prev_priority;


	ZONE_PADDING(_pad2_)
	/* Rarely used or read-mostly fields */

	/*
	 * wait_table		-- the array holding the hash table
	 * wait_table_size	-- the size of the hash table array
	 * wait_table_bits	-- wait_table_size == (1 << wait_table_bits)
	 *
	 * The purpose of all these is to keep track of the people
	 * waiting for a page to become available and make them
	 * runnable again when possible. The trouble is that this
	 * consumes a lot of space, especially when so few things
	 * wait on pages at a given time. So instead of using
	 * per-page waitqueues, we use a waitqueue hash table.
	 *
	 * The bucket discipline is to sleep on the same queue when
	 * colliding and wake all in that wait queue when removing.
	 * When something wakes, it must check to be sure its page is
	 * truly available, a la thundering herd. The cost of a
	 * collision is great, but given the expected load of the
	 * table, they should be so rare as to be outweighed by the
	 * benefits from the saved space.
	 *
	 * __wait_on_page_locked() and unlock_page() in mm/filemap.c, are the
	 * primary users of these fields, and in mm/page_alloc.c
	 * free_area_init_core() performs the initialization of them.
	 */
	wait_queue_head_t	* wait_table;
	unsigned long		wait_table_size;
	unsigned long		wait_table_bits;

	/*
	 * Discontig memory support fields.
	 */
	struct pglist_data	*zone_pgdat;
	struct page		*zone_mem_map;
	/* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
	unsigned long		zone_start_pfn;

	unsigned long		spanned_pages;	/* total size, including holes */
	unsigned long		present_pages;	/* amount of memory (excluding holes) */

	/*
	 * rarely used fields:
	 */
	char			*name;
} ____cacheline_maxaligned_in_smp;


/*
 * The "priority" of VM scanning is how much of the queues we will scan in one
 * go. A value of 12 for DEF_PRIORITY implies that we will scan 1/4096th of the
 * queues ("queue_length >> 12") during an aging round.
 */
#define DEF_PRIORITY 12

/*
 * One allocation request operates on a zonelist. A zonelist
 * is a list of zones, the first one is the 'goal' of the
 * allocation, the other zones are fallback zones, in decreasing
 * priority.
 *
 * Right now a zonelist takes up less than a cacheline. We never
 * modify it apart from boot-up, and only a few indices are used,
 * so despite the zonelist table being relatively big, the cache
 * footprint of this construct is very small.
 */

/*
*	管理区描述符指针数组
*	zonlist在内存分配请求中指定首选管理区,
*/
struct zonelist {
	struct zone *zones[MAX_NUMNODES * MAX_NR_ZONES + 1]; // NULL delimited
};


/*
 * The pg_data_t structure is used in machines with CONFIG_DISCONTIGMEM
 * (mostly NUMA machines?) to denote a higher-level memory zone than the
 * zone denotes.
 *
 * On NUMA machines, each NUMA node would have a pg_data_t to describe
 * it's memory layout.
 *
 * Memory statistics and page replacement data structures are maintained on a
 * per-zone basis.
 */
struct bootmem_data;
typedef struct pglist_data {
	/*节点中管理区描述符的数组*/
	struct zone node_zones[MAX_NR_ZONES];
	/*页分配器使用zonelist数据结构放入数组*/
	struct zonelist node_zonelists[GFP_ZONETYPES];
	/*节点中管理区的个数*/
	int nr_zones;
	/*节点中页描述符的数组*/
	struct page *node_mem_map;
	/*用在内核初始化阶段*/
	struct bootmem_data *bdata;
	/*节点中第一个页框的下标*/
	unsigned long node_start_pfn;
	/*内存节点的大小，不包括洞（以页框为单位）*/
	unsigned long node_present_pages; /* total number of physical pages */
	/*节点的大小，包括洞(以页框为单位)*/
	unsigned long node_spanned_pages; /* total size of physical page
					     range, including holes */
	/*节点标识符*/
	int node_id;
	/*内存节点链表中的下一项*/
	struct pglist_data *pgdat_next;
	/*kswapd页换出守护进程使用放入等待队列*/
	wait_queue_head_t kswapd_wait;
	/*指针指向kswapd内核线程的进程描述符*/
	struct task_struct *kswapd;
	/*kswapd将要创建的空闲块大小取对数的值*/
	int kswapd_max_order;
} pg_data_t;

#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)

extern struct pglist_data *pgdat_list;

void __get_zone_counts(unsigned long *active, unsigned long *inactive,
			unsigned long *free, struct pglist_data *pgdat);
void get_zone_counts(unsigned long *active, unsigned long *inactive,
			unsigned long *free);
void build_all_zonelists(void);
void wakeup_kswapd(struct zone *zone, int order);
int zone_watermark_ok(struct zone *z, int order, unsigned long mark,
		int alloc_type, int can_try_harder, int gfp_high);

/*
 * zone_idx() returns 0 for the ZONE_DMA zone, 1 for the ZONE_NORMAL zone, etc.
 */
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)

/**
 * for_each_pgdat - helper macro to iterate over all nodes
 * @pgdat - pointer to a pg_data_t variable
 *
 * Meant to help with common loops of the form
 * pgdat = pgdat_list;
 * while(pgdat) {
 * 	...
 * 	pgdat = pgdat->pgdat_next;
 * }
 */
#define for_each_pgdat(pgdat) \
	for (pgdat = pgdat_list; pgdat; pgdat = pgdat->pgdat_next)

/*
 * next_zone - helper magic for for_each_zone()
 * Thanks to William Lee Irwin III for this piece of ingenuity.
 */
static inline struct zone *next_zone(struct zone *zone)
{
	pg_data_t *pgdat = zone->zone_pgdat;

	if (zone < pgdat->node_zones + MAX_NR_ZONES - 1)
		zone++;
	else if (pgdat->pgdat_next) {
		pgdat = pgdat->pgdat_next;
		zone = pgdat->node_zones;
	} else
		zone = NULL;

	return zone;
}

/**
 * for_each_zone - helper macro to iterate over all memory zones
 * @zone - pointer to struct zone variable
 *
 * The user only needs to declare the zone variable, for_each_zone
 * fills it in. This basically means for_each_zone() is an
 * easier to read version of this piece of code:
 *
 * for (pgdat = pgdat_list; pgdat; pgdat = pgdat->node_next)
 * 	for (i = 0; i < MAX_NR_ZONES; ++i) {
 * 		struct zone * z = pgdat->node_zones + i;
 * 		...
 * 	}
 * }
 */
#define for_each_zone(zone) \
	for (zone = pgdat_list->node_zones; zone; zone = next_zone(zone))

static inline int is_highmem_idx(int idx)
{
	return (idx == ZONE_HIGHMEM);
}

static inline int is_normal_idx(int idx)
{
	return (idx == ZONE_NORMAL);
}
/**
 * is_highmem - helper function to quickly check if a struct zone is a 
 *              highmem zone or not.  This is an attempt to keep references
 *              to ZONE_{DMA/NORMAL/HIGHMEM/etc} in general code to a minimum.
 * @zone - pointer to struct zone variable
 */
static inline int is_highmem(struct zone *zone)
{
	return zone == zone->zone_pgdat->node_zones + ZONE_HIGHMEM;
}

static inline int is_normal(struct zone *zone)
{
	return zone == zone->zone_pgdat->node_zones + ZONE_NORMAL;
}

/* These two functions are used to setup the per zone pages min values */
struct ctl_table;
struct file;
int min_free_kbytes_sysctl_handler(struct ctl_table *, int, struct file *, 
					void __user *, size_t *, loff_t *);
extern int sysctl_lowmem_reserve_ratio[MAX_NR_ZONES-1];
int lowmem_reserve_ratio_sysctl_handler(struct ctl_table *, int, struct file *,
					void __user *, size_t *, loff_t *);

#include <linux/topology.h>
/* Returns the number of the current Node. */
#define numa_node_id()		(cpu_to_node(_smp_processor_id()))

#ifndef CONFIG_DISCONTIGMEM

/*
*	节点0的描述符
*	它的node_zonelists字段是一个管理区描述符链表的数组,代表后备管理区
*/
extern struct pglist_data contig_page_data;
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map
#define MAX_NODES_SHIFT		1
#define pfn_to_nid(pfn)		(0)

#else /* CONFIG_DISCONTIGMEM */

#include <asm/mmzone.h>

#if BITS_PER_LONG == 32 || defined(ARCH_HAS_ATOMIC_UNSIGNED)
/*
 * with 32 bit page->flags field, we reserve 8 bits for node/zone info.
 * there are 3 zones (2 bits) and this leaves 8-2=6 bits for nodes.
 */
#define MAX_NODES_SHIFT		6
#elif BITS_PER_LONG == 64
/*
 * with 64 bit flags field, there's plenty of room.
 */
#define MAX_NODES_SHIFT		10
#endif

#endif /* !CONFIG_DISCONTIGMEM */

#if NODES_SHIFT > MAX_NODES_SHIFT
#error NODES_SHIFT > MAX_NODES_SHIFT
#endif

/* There are currently 3 zones: DMA, Normal & Highmem, thus we need 2 bits */
#define MAX_ZONES_SHIFT		2

#if ZONES_SHIFT > MAX_ZONES_SHIFT
#error ZONES_SHIFT > MAX_ZONES_SHIFT
#endif

#endif /* !__ASSEMBLY__ */
#endif /* __KERNEL__ */
#endif /* _LINUX_MMZONE_H */
