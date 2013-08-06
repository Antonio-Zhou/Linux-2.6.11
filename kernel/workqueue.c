/*
 * linux/kernel/workqueue.c
 *
 * Generic mechanism for defining kernel helper threads for running
 * arbitrary tasks in process context.
 *
 * Started by Ingo Molnar, Copyright (C) 2002
 *
 * Derived from the taskqueue/keventd code by:
 *
 *   David Woodhouse <dwmw2@infradead.org>
 *   Andrew Morton <andrewm@uow.edu.au>
 *   Kai Petzke <wpp@marie.physik.tu-berlin.de>
 *   Theodore Ts'o <tytso@mit.edu>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/signal.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/kthread.h>

/*
 * The per-CPU workqueue (if single thread, we always use cpu 0's).
 *
 * The sequence counters are for flush_scheduled_work().  It wants to wait
 * until until all currently-scheduled works are completed, but it doesn't
 * want to be livelocked by new, incoming ones.  So it waits until
 * remove_sequence is >= the insert_sequence which pertained when
 * flush_scheduled_work() was called.
 */

/*
 * cpu_workqueue_struct结构的worklist是双向链表的头, 集中了工作队列中的所有挂起函数
 * work_struct数据结构用来表示每一个挂起函数
 * */
struct cpu_workqueue_struct {

	/*保护该数据结构的自旋锁*/
	spinlock_t lock;

	/* flush_scheduled_work()使用的序列号*/
	long remove_sequence;	/* Least-recently added (next to run) */
	/* flush_scheduled_work()使用的序列号*/
	long insert_sequence;	/* Next to add */
	/*挂起链表的头结点*/
	struct list_head worklist;
	/*等待队列,其中的工作者线程因等待更多的工作而处于睡眠状态*/
	wait_queue_head_t more_work;
	/*等待队列,其中的进程由于等待工作队列被刷新而处于睡眠状态*/
	wait_queue_head_t work_done;
	/*指向workqueue_struct结构的指针,其中包含该描述符*/
	struct workqueue_struct *wq;
	/*指向结构中工作者线程的进程描述符指针*/
	task_t *thread;
	/*run_workqueue()当前的执行深度(当工作队列链表中的函数阻塞时,这个字段的值会变得比1大)*/
	int run_depth;		/* Detect run_workqueue() recursion depth */
} ____cacheline_aligned;

/*
 * The externally visible workqueue abstraction is an array of
 * per-CPU workqueues:
 */
struct workqueue_struct {
	/*NR_CPUS是系统中CPU的最大数量*/
	struct cpu_workqueue_struct cpu_wq[NR_CPUS];
	const char *name;
	struct list_head list; 	/* Empty if single thread */
};

/* All the per-cpu workqueues on the system, for hotplug cpu to add/remove
   threads to each one as cpus come/go. */
static DEFINE_SPINLOCK(workqueue_lock);
static LIST_HEAD(workqueues);

/* If it's single threaded, it isn't in the list of workqueues. */
static inline int is_single_threaded(struct workqueue_struct *wq)
{
	return list_empty(&wq->list);
}

/* Preempt must be disabled. */
static void __queue_work(struct cpu_workqueue_struct *cwq,
			 struct work_struct *work)
{
	unsigned long flags;

	spin_lock_irqsave(&cwq->lock, flags);
	work->wq_data = cwq;
	/*挂接*/
	list_add_tail(&work->entry, &cwq->worklist);
	/*递增插入的序列号*/
	cwq->insert_sequence++;
	wake_up(&cwq->more_work);
	spin_unlock_irqrestore(&cwq->lock, flags);
}

/*
 * Queue work on a workqueue. Return non-zero if it was successfully
 * added.
 *
 * We queue the work to the CPU it was submitted, but there is no
 * guarantee that it will be processed by that CPU.
 */

/*
 * 把函数插入工作队列,
 * 参数:struct workqueue_struct *wq---指向workqueue_struct描述符
 * 	struct work_struct *work---指向work_struct描述符
 * */
int fastcall queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	int ret = 0, cpu = get_cpu();

	/*检查要插入的函数是否已经在工作队列中*/
	if (!test_and_set_bit(0, &work->pending)) {
		/*工作结构还没在队列,设置pending标志表示把工作结构挂接到队列中*/
		if (unlikely(is_single_threaded(wq)))
			cpu = 0;
		BUG_ON(!list_empty(&work->entry));
		/*把work_struct描述符加到工作队列链表中*/
		__queue_work(wq->cpu_wq + cpu, work);
		ret = 1;
	}
	put_cpu();
	return ret;
}

/*
 * 定时中断函数
 * */
static void delayed_work_timer_fn(unsigned long __data)
{
	struct work_struct *work = (struct work_struct *)__data;
	struct workqueue_struct *wq = work->wq_data;
	int cpu = smp_processor_id();

	if (unlikely(is_single_threaded(wq)))
		cpu = 0;

	/*将工作结构添加到工作队列,注意这是在时间中断调用*/
	__queue_work(wq->cpu_wq + cpu, work);
}

/*
 * 与queue_work()几乎相同,
 * 只是queue_delayed_work()函数多接收一个以系统嘀嗒数来表示时间延迟,确保挂起函数在执行前的等待时间尽可能短
 * */
int fastcall queue_delayed_work(struct workqueue_struct *wq,
			struct work_struct *work, unsigned long delay)
{
	int ret = 0;
	/*定时器,此时的定时器应该死不起效的,延迟将通过该定时器实现*/
	struct timer_list *timer = &work->timer;

	/*工作结构还没有在队列,设置pending标志表示把工作结构挂接到队列中*/
	if (!test_and_set_bit(0, &work->pending)) {
		/*现在定时器生效,出错*/
		BUG_ON(timer_pending(timer));
		/*工作结构已经挂接到链表,出错*/
		BUG_ON(!list_empty(&work->entry));

		/* This stores wq for the moment, for the timer_fn */
		/*保存工作队列指针*/
		work->wq_data = wq;
		timer->expires = jiffies + delay;
		timer->data = (unsigned long)work;
		/*定时 函数*/
		timer->function = delayed_work_timer_fn;
		/*定时器生效,定时到期后再添加到工作队列*/
		add_timer(timer);
		ret = 1;
	}
	return ret;
}

static inline void run_workqueue(struct cpu_workqueue_struct *cwq)
{
	unsigned long flags;

	/*
	 * Keep taking off work from the queue until
	 * done.
	 */
	spin_lock_irqsave(&cwq->lock, flags);
	/*统计递归调用的次数*/
	cwq->run_depth++;
	/*调度太多*/
	if (cwq->run_depth > 3) {
		/* morton gets to eat his hat */
		printk("%s: recursion depth exceeded: %d\n",
			__FUNCTION__, cwq->run_depth);
		dump_stack();
	}
	/*遍历工作链表*/
	while (!list_empty(&cwq->worklist)) {
		/*获取的是next节点*/
		struct work_struct *work = list_entry(cwq->worklist.next,
						struct work_struct, entry);
		void (*f) (void *) = work->func;
		void *data = work->data;

		/*删除节点,同时节点中的list参数清空*/
		list_del_init(cwq->worklist.next);
		spin_unlock_irqrestore(&cwq->lock, flags);

		/*
		 * 现在执行以下代码时可以中断,run_workqueue本身可能会重新被调度
		 * 所以要判断递归深度
		 * */
		BUG_ON(work->wq_data != cwq);
		/*工作结构已经不再链表中*/
		clear_bit(0, &work->pending);
		/*执行工作函数*/
		f(data);

		spin_lock_irqsave(&cwq->lock, flags);
		/*执行完的工作序列号递增*/
		cwq->remove_sequence++;
		wake_up(&cwq->work_done);
	}
	/*减少递归深度*/
	cwq->run_depth--;
	spin_unlock_irqrestore(&cwq->lock, flags);
}

static int worker_thread(void *__cwq)
{
	struct cpu_workqueue_struct *cwq = __cwq;
	/*声明一个等待队列*/
	DECLARE_WAITQUEUE(wait, current);
	/*信号*/
	struct k_sigaction sa;
	sigset_t blocked;

	current->flags |= PF_NOFREEZE;
	
	/*降低进程优先级,工作进程不是个很紧急的进程,不和其他进程抢占CPU,通常在系统空闲时运行*/
	set_user_nice(current, -5);

	/* Block and flush all signals */
	/*阻塞所有信号*/
	sigfillset(&blocked);
	sigprocmask(SIG_BLOCK, &blocked, NULL);
	flush_signals(current);

	/* SIG_IGN makes children autoreap: see do_notify_parent(). */
	/*信号处理都忽略*/
	sa.sa.sa_handler = SIG_IGN;
	sa.sa.sa_flags = 0;
	siginitset(&sa.sa.sa_mask, sigmask(SIGCHLD));
	do_sigaction(SIGCHLD, &sa, (struct k_sigaction *)0);

	/*进程可中断*/
	set_current_state(TASK_INTERRUPTIBLE);
	/*没停止该进程就一直运行*/
	while (!kthread_should_stop()) {
		/*设置more_work等待队列,当有新work结构链入队列时,激发此等待队列*/
		add_wait_queue(&cwq->more_work, &wait);
		if (list_empty(&cwq->worklist))
			/*工作队列为空,睡眠*/
			schedule();
		else
			/*运行状态*/
			__set_current_state(TASK_RUNNING);
		/*删除等待队列*/
		remove_wait_queue(&cwq->more_work, &wait);

		/*按链表遍历,执行工作任务*/
		if (!list_empty(&cwq->worklist))
			run_workqueue(cwq);
		/*执行完工作,设置进程是可中断的,重新循环等待工作*/
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

static void flush_cpu_workqueue(struct cpu_workqueue_struct *cwq)
{
	if (cwq->thread == current) {
		/*
		 * Probably keventd trying to flush its own queue. So simply run
		 * it by hand rather than deadlocking.
		 */

		 /*如果是工作队列进程正在被调度,执行完该工作队列*/
		run_workqueue(cwq);
	} else {
		DEFINE_WAIT(wait);
		long sequence_needed;

		spin_lock_irq(&cwq->lock);
		/*最新工作结构序号*/
		sequence_needed = cwq->insert_sequence;
		/*判断队列中是否有还有未执行的工作结构*/
		while (sequence_needed - cwq->remove_sequence > 0) {
			/*有未执行的,通过work_done等待*/
			prepare_to_wait(&cwq->work_done, &wait,
					TASK_UNINTERRUPTIBLE);
			spin_unlock_irq(&cwq->lock);
			/*睡眠,由wake_up(&cwq->work_done)唤醒*/
			schedule();
			spin_lock_irq(&cwq->lock);
		}
		/*等待清除*/
		finish_wait(&cwq->work_done, &wait);
		spin_unlock_irq(&cwq->lock);
	}
}

/*
 * flush_workqueue - ensure that any scheduled work has run to completion.
 *
 * Forces execution of the workqueue and blocks until its completion.
 * This is typically used in driver shutdown handlers.
 *
 * This function will sample each workqueue's current insert_sequence number and
 * will sleep until the head sequence is greater than or equal to that.  This
 * means that we sleep until all works which were queued on entry have been
 * handled, but we are not livelocked by new incoming ones.
 *
 * This function used to run the workqueues itself.  Now we just wait for the
 * helper threads to do it.
 */
void fastcall flush_workqueue(struct workqueue_struct *wq)
{
	/*进程可以睡眠*/
	might_sleep();

	/*清空每个CPU上的工作队列*/
	if (is_single_threaded(wq)) {
		/* Always use cpu 0's area. */
		flush_cpu_workqueue(wq->cpu_wq + 0);
	} else {
		int cpu;

		lock_cpu_hotplug();
		for_each_online_cpu(cpu)
			flush_cpu_workqueue(wq->cpu_wq + cpu);
		unlock_cpu_hotplug();
	}
}

/*
 * 创建工作队列线程
 * */
static struct task_struct *create_workqueue_thread(struct workqueue_struct *wq,
						   int cpu)
{
	/*每个CPU的工作队列*/
	struct cpu_workqueue_struct *cwq = wq->cpu_wq + cpu;
	struct task_struct *p;

	spin_lock_init(&cwq->lock);
	/*初始化*/
	cwq->wq = wq;
	cwq->thread = NULL;
	cwq->insert_sequence = 0;
	cwq->remove_sequence = 0;
	INIT_LIST_HEAD(&cwq->worklist);
	/*初始化等待队列more_work,处理要执行的工作结构*/
	init_waitqueue_head(&cwq->more_work);
	/*初始化等待队列work_done,处理执行完的工作结构*/
	init_waitqueue_head(&cwq->work_done);

	/*建立内核线程work_thread*/
	if (is_single_threaded(wq))
		p = kthread_create(worker_thread, cwq, "%s", wq->name);
	else
		p = kthread_create(worker_thread, cwq, "%s/%d", wq->name, cpu);
	if (IS_ERR(p))
		return NULL;
	/*保存线程指针*/
	cwq->thread = p;
	return p;
}

struct workqueue_struct *__create_workqueue(const char *name,
					    int singlethread)
{
	int cpu, destroy = 0;
	struct workqueue_struct *wq;
	struct task_struct *p;

	BUG_ON(strlen(name) > 10);

	/*分配工作队列结构空间*/
	wq = kmalloc(sizeof(*wq), GFP_KERNEL);
	if (!wq)
		return NULL;
	memset(wq, 0, sizeof(*wq));

	wq->name = name;
	/* We don't need the distraction of CPUs appearing and vanishing. */
	lock_cpu_hotplug();
	/*
	 * 使用create_workqueue宏时，该参数始终为0
	 * 如果是单一模式,在单线程中调用各个工作队列,建立一个的工作队列内核线程
	 * */
	if (singlethread) {
		INIT_LIST_HEAD(&wq->list);
		/*建立工作队列的线程*/
		p = create_workqueue_thread(wq, 0);
		if (!p)
			destroy = 1;
		else
			/*唤醒该线程*/
			wake_up_process(p);
	} else {
		spin_lock(&workqueue_lock);
		/*链表模式,将工作队列添加到工作队列链表*/
		list_add(&wq->list, &workqueues);
		spin_unlock(&workqueue_lock);
		/*为每个CPU建立一个工作队列线程*/
		for_each_online_cpu(cpu) {
			p = create_workqueue_thread(wq, cpu);
			if (p) {
				/*绑定CPU*/
				kthread_bind(p, cpu);
				/*唤醒线程*/
				wake_up_process(p);
			} else
				destroy = 1;
		}
	}
	unlock_cpu_hotplug();

	/*
	 * Was there any error during startup? If yes then clean up:
	 */
	if (destroy) {
		/*建立线程失败,释放工作队列*/
		destroy_workqueue(wq);
		wq = NULL;
	}
	return wq;
}

static void cleanup_workqueue_thread(struct workqueue_struct *wq, int cpu)
{
	struct cpu_workqueue_struct *cwq;
	unsigned long flags;
	struct task_struct *p;

	cwq = wq->cpu_wq + cpu;
	spin_lock_irqsave(&cwq->lock, flags);
	p = cwq->thread;
	cwq->thread = NULL;
	spin_unlock_irqrestore(&cwq->lock, flags);
	if (p)
		kthread_stop(p);
}

void destroy_workqueue(struct workqueue_struct *wq)
{
	int cpu;

	/*清除当前工作队列中的所有工作*/
	flush_workqueue(wq);

	/* We don't need the distraction of CPUs appearing and vanishing. */
	lock_cpu_hotplug();
	/*结束该工作队列的线程*/
	if (is_single_threaded(wq))
		cleanup_workqueue_thread(wq, 0);
	else {
		for_each_online_cpu(cpu)
			cleanup_workqueue_thread(wq, cpu);
		spin_lock(&workqueue_lock);
		list_del(&wq->list);
		spin_unlock(&workqueue_lock);
	}
	unlock_cpu_hotplug();
	kfree(wq);
}

/*预定义工作队列*/
static struct workqueue_struct *keventd_wq;

/*
 * 调度工作结构,将工作结构添加到事件工作队列kevent_wq
 * */
int fastcall schedule_work(struct work_struct *work)
{
	return queue_work(keventd_wq, work);
}

/*
 * 延迟调度工作,延迟一定时间后再将工作结构挂接到工作队列
 * */
int fastcall schedule_delayed_work(struct work_struct *work, unsigned long delay)
{
	return queue_delayed_work(keventd_wq, work, delay);
}

int schedule_delayed_work_on(int cpu,
			struct work_struct *work, unsigned long delay)
{
	int ret = 0;
	struct timer_list *timer = &work->timer;

	if (!test_and_set_bit(0, &work->pending)) {
		BUG_ON(timer_pending(timer));
		BUG_ON(!list_empty(&work->entry));
		/* This stores keventd_wq for the moment, for the timer_fn */
		work->wq_data = keventd_wq;
		timer->expires = jiffies + delay;
		timer->data = (unsigned long)work;
		timer->function = delayed_work_timer_fn;
		add_timer_on(timer, cpu);
		ret = 1;
	}
	return ret;
}

void flush_scheduled_work(void)
{
	flush_workqueue(keventd_wq);
}

int keventd_up(void)
{
	return keventd_wq != NULL;
}

int current_is_keventd(void)
{
	struct cpu_workqueue_struct *cwq;
	int cpu = smp_processor_id();	/* preempt-safe: keventd is per-cpu */
	int ret = 0;

	BUG_ON(!keventd_wq);

	cwq = keventd_wq->cpu_wq + cpu;
	if (current == cwq->thread)
		ret = 1;

	return ret;

}

#ifdef CONFIG_HOTPLUG_CPU
/* Take the work from this (downed) CPU. */
static void take_over_work(struct workqueue_struct *wq, unsigned int cpu)
{
	struct cpu_workqueue_struct *cwq = wq->cpu_wq + cpu;
	LIST_HEAD(list);
	struct work_struct *work;

	spin_lock_irq(&cwq->lock);
	list_splice_init(&cwq->worklist, &list);

	while (!list_empty(&list)) {
		printk("Taking work for %s\n", wq->name);
		work = list_entry(list.next,struct work_struct,entry);
		list_del(&work->entry);
		__queue_work(wq->cpu_wq + smp_processor_id(), work);
	}
	spin_unlock_irq(&cwq->lock);
}

/* We're holding the cpucontrol mutex here */
static int __devinit workqueue_cpu_callback(struct notifier_block *nfb,
				  unsigned long action,
				  void *hcpu)
{
	unsigned int hotcpu = (unsigned long)hcpu;
	struct workqueue_struct *wq;

	switch (action) {
	case CPU_UP_PREPARE:
		/* Create a new workqueue thread for it. */
		list_for_each_entry(wq, &workqueues, list) {
			if (create_workqueue_thread(wq, hotcpu) < 0) {
				printk("workqueue for %i failed\n", hotcpu);
				return NOTIFY_BAD;
			}
		}
		break;

	case CPU_ONLINE:
		/* Kick off worker threads. */
		list_for_each_entry(wq, &workqueues, list) {
			kthread_bind(wq->cpu_wq[hotcpu].thread, hotcpu);
			wake_up_process(wq->cpu_wq[hotcpu].thread);
		}
		break;

	case CPU_UP_CANCELED:
		list_for_each_entry(wq, &workqueues, list) {
			/* Unbind so it can run. */
			kthread_bind(wq->cpu_wq[hotcpu].thread,
				     smp_processor_id());
			cleanup_workqueue_thread(wq, hotcpu);
		}
		break;

	case CPU_DEAD:
		list_for_each_entry(wq, &workqueues, list)
			cleanup_workqueue_thread(wq, hotcpu);
		list_for_each_entry(wq, &workqueues, list)
			take_over_work(wq, hotcpu);
		break;
	}

	return NOTIFY_OK;
}
#endif

void init_workqueues(void)
{
	hotcpu_notifier(workqueue_cpu_callback, 0);
	keventd_wq = create_workqueue("events");
	BUG_ON(!keventd_wq);
}

EXPORT_SYMBOL_GPL(__create_workqueue);
EXPORT_SYMBOL_GPL(queue_work);
EXPORT_SYMBOL_GPL(queue_delayed_work);
EXPORT_SYMBOL_GPL(flush_workqueue);
EXPORT_SYMBOL_GPL(destroy_workqueue);

EXPORT_SYMBOL(schedule_work);
EXPORT_SYMBOL(schedule_delayed_work);
EXPORT_SYMBOL(schedule_delayed_work_on);
EXPORT_SYMBOL(flush_scheduled_work);
