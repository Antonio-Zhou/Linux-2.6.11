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
*	cpu_workqueue_struct�ṹ��worklist��˫�������ͷ,
*	�����˹��������е����й�����
*	work_struct���ݽṹ������ʾÿһ��������
*/
struct cpu_workqueue_struct {

	spinlock_t lock;			/*���������ݽṹ��������*/

	long remove_sequence;	/* Least-recently added (next to run) *//* flush_scheduled_work()ʹ�õ����к�*/
	long insert_sequence;	/* Next to add */ /* flush_scheduled_work()ʹ�õ����к�*/

	struct list_head worklist;	/*���������ͷ���*/
	wait_queue_head_t more_work;		/*�ȴ�����,���еĹ������߳���ȴ�����Ĺ���������˯��״̬*/
	wait_queue_head_t work_done;		/*�ȴ�����,���еĽ������ڵȴ��������б�ˢ�¶�����˯��״̬*/

	struct workqueue_struct *wq;		/*ָ��workqueue_struct�ṹ��ָ��,���а�����������*/
	task_t *thread;					/*ָ��ṹ�й������̵߳Ľ���������ָ��*/

	int run_depth;		/* Detect run_workqueue() recursion depth */	/*run_workqueue()��ǰ��ִ�����(���������������еĺ�������ʱ,����ֶε�ֵ���ñ�1��)*/
} ____cacheline_aligned;

/*
 * The externally visible workqueue abstraction is an array of
 * per-CPU workqueues:
 */
struct workqueue_struct {
	struct cpu_workqueue_struct cpu_wq[NR_CPUS];	/*NR_CPUS��ϵͳ��CPU���������*/
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
	/*�ҽ�*/
	list_add_tail(&work->entry, &cwq->worklist);
	/*������������к�*/
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
*	�Ѻ������빤������,
*	wq---ָ��workqueue_struct������
*	work---ָ��work_struct������
*/
int fastcall queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	int ret = 0, cpu = get_cpu();

	/*���Ҫ����ĺ����Ƿ��Ѿ��ڹ���������*/
	if (!test_and_set_bit(0, &work->pending)) {
		/*�����ṹ��û�ڶ���,����pending��־��ʾ�ѹ����ṹ�ҽӵ�������*/
		if (unlikely(is_single_threaded(wq)))
			cpu = 0;
		BUG_ON(!list_empty(&work->entry));
		/*��work_struct�������ӵ���������������*/
		__queue_work(wq->cpu_wq + cpu, work);
		ret = 1;
	}
	put_cpu();
	return ret;
}

/*��ʱ�жϺ���*/
static void delayed_work_timer_fn(unsigned long __data)
{
	struct work_struct *work = (struct work_struct *)__data;
	struct workqueue_struct *wq = work->wq_data;
	int cpu = smp_processor_id();

	if (unlikely(is_single_threaded(wq)))
		cpu = 0;

	/*�������ṹ��ӵ���������,ע��������ʱ���жϵ���*/
	__queue_work(wq->cpu_wq + cpu, work);
}

/*
*	��queue_work()������ͬ,
*	ֻ��queue_delayed_work()���������һ����ϵͳ���������ʾʱ���ӳ�
*	ȷ����������ִ��ǰ�ĵȴ�ʱ�価���ܶ�
*/
int fastcall queue_delayed_work(struct workqueue_struct *wq,
			struct work_struct *work, unsigned long delay)
{
	int ret = 0;
	/*��ʱ��,��ʱ�Ķ�ʱ��Ӧ��������Ч��,�ӳٽ�ͨ���ö�ʱ��ʵ��*/
	struct timer_list *timer = &work->timer;

	/*�����ṹ��û���ڶ���,����pending��־��ʾ�ѹ����ṹ�ҽӵ�������*/
	if (!test_and_set_bit(0, &work->pending)) {
		/*���ڶ�ʱ����Ч,����*/
		BUG_ON(timer_pending(timer));
		/*�����ṹ�Ѿ��ҽӵ�����,����*/
		BUG_ON(!list_empty(&work->entry));

		/* This stores wq for the moment, for the timer_fn */
		/*���湤������ָ��*/
		work->wq_data = wq;
		timer->expires = jiffies + delay;
		timer->data = (unsigned long)work;
		/*��ʱ ����*/
		timer->function = delayed_work_timer_fn;
		/*��ʱ����Ч,��ʱ���ں�����ӵ���������*/
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
	/*ͳ�Ƶݹ���õĴ���*/
	cwq->run_depth++;
	/*����̫��*/
	if (cwq->run_depth > 3) {
		/* morton gets to eat his hat */
		printk("%s: recursion depth exceeded: %d\n",
			__FUNCTION__, cwq->run_depth);
		dump_stack();
	}
	/*������������*/
	while (!list_empty(&cwq->worklist)) {
		/*��ȡ����next�ڵ�*/
		struct work_struct *work = list_entry(cwq->worklist.next,
						struct work_struct, entry);
		void (*f) (void *) = work->func;
		void *data = work->data;

		/*ɾ���ڵ�,ͬʱ�ڵ��е�list�������*/
		list_del_init(cwq->worklist.next);
		spin_unlock_irqrestore(&cwq->lock, flags);

		/*
		*	����ִ�����´���ʱ�����ж�,run_workqueue������ܻ����±�����
		*	����Ҫ�жϵݹ����
		*/
		BUG_ON(work->wq_data != cwq);
		/*�����ṹ�Ѿ�����������*/
		clear_bit(0, &work->pending);
		/*ִ�й�������*/
		f(data);

		spin_lock_irqsave(&cwq->lock, flags);
		/*ִ����Ĺ������кŵ���*/
		cwq->remove_sequence++;
		wake_up(&cwq->work_done);
	}
	/*���ٵݹ����*/
	cwq->run_depth--;
	spin_unlock_irqrestore(&cwq->lock, flags);
}

static int worker_thread(void *__cwq)
{
	struct cpu_workqueue_struct *cwq = __cwq;
	/*����һ���ȴ�����*/
	DECLARE_WAITQUEUE(wait, current);
	/*�ź�*/
	struct k_sigaction sa;
	sigset_t blocked;

	current->flags |= PF_NOFREEZE;
	
	/*���ͽ������ȼ�,�������̲��Ǹ��ܽ����Ľ���,��������������ռCPU,ͨ����ϵͳ����ʱ����*/
	set_user_nice(current, -5);

	/* Block and flush all signals */
	/*���������ź�*/
	sigfillset(&blocked);
	sigprocmask(SIG_BLOCK, &blocked, NULL);
	flush_signals(current);

	/* SIG_IGN makes children autoreap: see do_notify_parent(). */
	/*�źŴ�������*/
	sa.sa.sa_handler = SIG_IGN;
	sa.sa.sa_flags = 0;
	siginitset(&sa.sa.sa_mask, sigmask(SIGCHLD));
	do_sigaction(SIGCHLD, &sa, (struct k_sigaction *)0);

	/*���̿��ж�*/
	set_current_state(TASK_INTERRUPTIBLE);
	/*ûֹͣ�ý��̾�һֱ����*/
	while (!kthread_should_stop()) {
		/*����more_work�ȴ�����,������work�ṹ�������ʱ,�����˵ȴ�����*/
		add_wait_queue(&cwq->more_work, &wait);
		if (list_empty(&cwq->worklist))
			/*��������Ϊ��,˯��*/
			schedule();
		else
			/*����״̬*/
			__set_current_state(TASK_RUNNING);
		/*ɾ���ȴ�����*/
		remove_wait_queue(&cwq->more_work, &wait);

		/*���������,ִ�й�������*/
		if (!list_empty(&cwq->worklist))
			run_workqueue(cwq);
		/*ִ���깤��,���ý����ǿ��жϵ�,����ѭ���ȴ�����*/
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
		 /*
		 *	����ǹ������н������ڱ�����,
		 *	ִ����ù�������
		*/
		run_workqueue(cwq);
	} else {
		DEFINE_WAIT(wait);
		long sequence_needed;

		spin_lock_irq(&cwq->lock);
		/*���¹����ṹ���*/
		sequence_needed = cwq->insert_sequence;
		/*�ж϶������Ƿ��л���δִ�еĹ����ṹ*/
		while (sequence_needed - cwq->remove_sequence > 0) {
			/*��δִ�е�,ͨ��work_done�ȴ�*/
			prepare_to_wait(&cwq->work_done, &wait,
					TASK_UNINTERRUPTIBLE);
			spin_unlock_irq(&cwq->lock);
			/*˯��,��wake_up(&cwq->work_done)����*/
			schedule();
			spin_lock_irq(&cwq->lock);
		}
		/*�ȴ����*/
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
	/*���̿���˯��*/
	might_sleep();

	/*���ÿ��CPU�ϵĹ�������*/
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

/*�������������߳�*/
static struct task_struct *create_workqueue_thread(struct workqueue_struct *wq,
						   int cpu)
{
	/*ÿ��CPU�Ĺ�������*/
	struct cpu_workqueue_struct *cwq = wq->cpu_wq + cpu;
	struct task_struct *p;

	spin_lock_init(&cwq->lock);
	/*��ʼ��*/
	cwq->wq = wq;
	cwq->thread = NULL;
	cwq->insert_sequence = 0;
	cwq->remove_sequence = 0;
	INIT_LIST_HEAD(&cwq->worklist);
	/*��ʼ���ȴ�����more_work,����Ҫִ�еĹ����ṹ*/
	init_waitqueue_head(&cwq->more_work);
	/*��ʼ���ȴ�����work_done,����ִ����Ĺ����ṹ*/
	init_waitqueue_head(&cwq->work_done);

	/*�����ں��߳�work_thread*/
	if (is_single_threaded(wq))
		p = kthread_create(worker_thread, cwq, "%s", wq->name);
	else
		p = kthread_create(worker_thread, cwq, "%s/%d", wq->name, cpu);
	if (IS_ERR(p))
		return NULL;
	/*�����߳�ָ��*/
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

	/*���乤�����нṹ�ռ�*/
	wq = kmalloc(sizeof(*wq), GFP_KERNEL);
	if (!wq)
		return NULL;
	memset(wq, 0, sizeof(*wq));

	wq->name = name;
	/* We don't need the distraction of CPUs appearing and vanishing. */
	lock_cpu_hotplug();
	/*
	*	ʹ��create_workqueue��ʱ���ò���ʼ��Ϊ0
	*	����ǵ�һģʽ,�ڵ��߳��е��ø�����������
	*	����һ���Ĺ��������ں��߳�
	*/
	if (singlethread) {
		INIT_LIST_HEAD(&wq->list);
		/*�����������е��߳�*/
		p = create_workqueue_thread(wq, 0);
		if (!p)
			destroy = 1;
		else
			/*���Ѹ��߳�*/
			wake_up_process(p);
	} else {
		spin_lock(&workqueue_lock);
		/*����ģʽ,������������ӵ�������������*/
		list_add(&wq->list, &workqueues);
		spin_unlock(&workqueue_lock);
		/*Ϊÿ��CPU����һ�����������߳�*/
		for_each_online_cpu(cpu) {
			p = create_workqueue_thread(wq, cpu);
			if (p) {
				/*��CPU*/
				kthread_bind(p, cpu);
				/*�����߳�*/
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
		/*�����߳�ʧ��,�ͷŹ�������*/
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

/**/
void destroy_workqueue(struct workqueue_struct *wq)
{
	int cpu;

	/*�����ǰ���������е����й���*/
	flush_workqueue(wq);

	/* We don't need the distraction of CPUs appearing and vanishing. */
	lock_cpu_hotplug();
	/*�����ù������е��߳�*/
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

/*Ԥ���幤������*/
static struct workqueue_struct *keventd_wq;

/*���ȹ����ṹ,�������ṹ��ӵ��¼���������kevent_wq*/
int fastcall schedule_work(struct work_struct *work)
{
	return queue_work(keventd_wq, work);
}

/*�ӳٵ��ȹ���,�ӳ�һ��ʱ����ٽ������ṹ�ҽӵ���������*/
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
