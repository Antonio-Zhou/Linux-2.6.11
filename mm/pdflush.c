/*
 * mm/pdflush.c - worker threads for writing back filesystem data
 *
 * Copyright (C) 2002, Linus Torvalds.
 *
 * 09Apr2002	akpm@zip.com.au
 *		Initial version
 * 29Feb2004	kaos@sgi.com
 *		Move worker thread creation to kthread to avoid chewing
 *		up stack space with nested calls to kernel_thread.
 */

#include <linux/sched.h>
#include <linux/list.h>
#include <linux/signal.h>
#include <linux/spinlock.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>		// Needed by writeback.h
#include <linux/writeback.h>	// Prototypes pdflush_operation()
#include <linux/kthread.h>


/*
 * Minimum and maximum number of pdflush instances
 */
#define MIN_PDFLUSH_THREADS	2
#define MAX_PDFLUSH_THREADS	8

static void start_one_pdflush_thread(void);


/*
 * The pdflush threads are worker threads for writing back dirty data.
 * Ideally, we'd like one thread per active disk spindle.  But the disk
 * topology is very hard to divine at this level.   Instead, we take
 * care in various places to prevent more than one pdflush thread from
 * performing writeback against a single filesystem.  pdflush threads
 * have the PF_FLUSHER flag set in current->flags to aid in this.
 */

/*
 * All the pdflush threads.  Protected by pdflush_lock
 */

/*空闲pdflush的描述符*/
static LIST_HEAD(pdflush_list);
/*SMP中。保护链表不被并发访问*/
static DEFINE_SPINLOCK(pdflush_lock);

/*
 * The count of currently-running pdflush threads.  Protected
 * by pdflush_lock.
 *
 * Readable by sysctl, but not writable.  Published to userspace at
 * /proc/sys/vm/nr_pdflush_threads.
 */

/*pdflush内核线程的总数*/
int nr_pdflush_threads = 0;

/*
 * The time at which the pdflush thread pool last went empty
 */

/*链表为空的时间*/
static unsigned long last_empty_jifs;

/*
 * The pdflush thread.
 *
 * Thread pool management algorithm:
 * 
 * - The minimum and maximum number of pdflush instances are bound
 *   by MIN_PDFLUSH_THREADS and MAX_PDFLUSH_THREADS.
 * 
 * - If there have been no idle pdflush instances for 1 second, create
 *   a new one.
 * 
 * - If the least-recently-went-to-sleep pdflush thread has been asleep
 *   for more than one second, terminate a thread.
 */

/*
 * A structure for passing work to a pdflush thread.  Also for passing
 * state information between pdflush threads.  Protected by pdflush_lock.
 */
struct pdflush_work {
	struct task_struct *who;	/* The thread */
	void (*fn)(unsigned long);	/* A callback function */
	unsigned long arg0;		/* An argument to the callback */
	struct list_head list;		/* On pdflush_list, when idle */
	unsigned long when_i_went_to_sleep;
};

static int __pdflush(struct pdflush_work *my_work)
{
	current->flags |= PF_FLUSHER;
	my_work->fn = NULL;
	my_work->who = current;
	INIT_LIST_HEAD(&my_work->list);

	spin_lock_irq(&pdflush_lock);
	nr_pdflush_threads++;

	/*循环执行，一直到内核线程死亡*/
	for ( ; ; ) {
		struct pdflush_work *pdf;

		set_current_state(TASK_INTERRUPTIBLE);
		list_move(&my_work->list, &pdflush_list);
		my_work->when_i_went_to_sleep = jiffies;
		spin_unlock_irq(&pdflush_lock);

		/*内核线程被唤醒*/
		schedule();
		if (try_to_freeze(PF_FREEZE)) {
			spin_lock_irq(&pdflush_lock);
			continue;
		}

		spin_lock_irq(&pdflush_lock);
		if (!list_empty(&my_work->list)) {
			printk("pdflush: bogus wakeup!\n");
			my_work->fn = NULL;
			continue;
		}
		if (my_work->fn == NULL) {
			printk("pdflush: NULL work function\n");
			continue;
		}
		spin_unlock_irq(&pdflush_lock);

		(*my_work->fn)(my_work->arg0);

		/*
		 * Thread creation: For how long have there been zero
		 * available threads?
		 */
		/*不存在空闲pdflush线程的时间超过1秒*/
		if (jiffies - last_empty_jifs > 1 * HZ) {
			/* unlocked list_empty() test is OK here */
			if (list_empty(&pdflush_list)) {
				/* unlocked test is OK here */
				/*pdflush内核线程数还没有到最大值*/
				if (nr_pdflush_threads < MAX_PDFLUSH_THREADS)
					/*创建另外一个线程*/
					start_one_pdflush_thread();
			}
		}

		spin_lock_irq(&pdflush_lock);
		my_work->fn = NULL;

		/*
		 * Thread destruction: For how long has the sleepiest
		 * thread slept?
		 */
		if (list_empty(&pdflush_list))
			continue;
		if (nr_pdflush_threads <= MIN_PDFLUSH_THREADS)
			continue;
		pdf = list_entry(pdflush_list.prev, struct pdflush_work, list);
		if (jiffies - pdf->when_i_went_to_sleep > 1 * HZ) {
			/* Limit exit rate */
			pdf->when_i_went_to_sleep = jiffies;
			break;					/* exeunt */
		}
	}
	nr_pdflush_threads--;
	spin_unlock_irq(&pdflush_lock);
	return 0;
}

/*
 * Of course, my_work wants to be just a local in __pdflush().  It is
 * separated out in this manner to hopefully prevent the compiler from
 * performing unfortunate optimisations against the auto variables.  Because
 * these are visible to other tasks and CPUs.  (No problem has actually
 * been observed.  This is just paranoia).
 */

/**/
static int pdflush(void *dummy)
{
	struct pdflush_work my_work;

	/*
	 * pdflush can spend a lot of time doing encryption via dm-crypt.  We
	 * don't want to do that at keventd's priority.
	 */
	set_user_nice(current, 0);
	return __pdflush(&my_work);
}

/*
 * Attempt to wake up a pdflush thread, and get it to do some work for you.
 * Returns zero if it indeed managed to find a worker thread, and passed your
 * payload to it.
 */

/*
 * 激活空闲的pdflush线程
 * 参数：void (*fn)(unsigned long)---指向必须执行的函数
 * 	 unsigned long arg0---参数
 * */
int pdflush_operation(void (*fn)(unsigned long), unsigned long arg0)
{
	unsigned long flags;
	int ret = 0;

	if (fn == NULL)
		BUG();		/* Hard to diagnose if it's deferred */

	spin_lock_irqsave(&pdflush_lock, flags);
	if (list_empty(&pdflush_list)) {
		spin_unlock_irqrestore(&pdflush_lock, flags);
		ret = -1;
	} else {
		struct pdflush_work *pdf;

		pdf = list_entry(pdflush_list.next, struct pdflush_work, list);
		list_del_init(&pdf->list);
		if (list_empty(&pdflush_list))
			last_empty_jifs = jiffies;
		pdf->fn = fn;
		pdf->arg0 = arg0;
		/*唤醒空闲的pdflush空闲进程*/
		wake_up_process(pdf->who);
		spin_unlock_irqrestore(&pdflush_lock, flags);
	}
	return ret;
}

static void start_one_pdflush_thread(void)
{
	kthread_run(pdflush, NULL, "pdflush");
}

static int __init pdflush_init(void)
{
	int i;

	for (i = 0; i < MIN_PDFLUSH_THREADS; i++)
		start_one_pdflush_thread();
	return 0;
}

module_init(pdflush_init);
