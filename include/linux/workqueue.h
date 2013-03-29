/*
 * workqueue.h --- work queue handling for Linux.
 */

#ifndef _LINUX_WORKQUEUE_H
#define _LINUX_WORKQUEUE_H

#include <linux/timer.h>
#include <linux/linkage.h>
#include <linux/bitops.h>

struct workqueue_struct;

/*表示每一个挂起函数*/
struct work_struct {
	unsigned long pending;	/*如果函数已经在工作队列链表中==1,否则==0*/
	struct list_head entry;		/*指向挂起函数链表前一个或后一个元素的指针*/
	void (*func)(void *);		/*挂起函数的地址*/
	void *data;				/*传递给挂起函数的参数,一个指针*/
	void *wq_data;			/*通常是指向cpu_workqueue_srtuct描述符的父结点的指针*/
	struct timer_list timer;		/*用于延迟挂起函数执行的软定时器*/
};

/*初始化工作队列*/
#define __WORK_INITIALIZER(n, f, d) {				\
	/*初始化list*/
        .entry	= { &(n).entry, &(n).entry },			\
        /*挂起函数*/
	.func = (f),						\
	/*挂起函数参数*/
	.data = (d),						\
	/*初始化定时器*/
	.timer = TIMER_INITIALIZER(NULL, 0, 0),			\
	}

/*声明工作队列,并初始化*/
#define DECLARE_WORK(n, f, d)					\
	struct work_struct n = __WORK_INITIALIZER(n, f, d)

/*
 * initialize a work-struct's func and data pointers:
 */
 /*重新定义工作结构参数*/
#define PREPARE_WORK(_work, _func, _data)			\
	do {							\
		(_work)->func = _func;				\
		(_work)->data = _data;				\
	} while (0)

/*
 * initialize all of a work-struct:
 */
 /*
 *	初始化工作结构,和__WORK_INITIALIZER功能相同,不过__WORK_INITIALIZER用在参数初始化定义
 *	而该宏用在程序之中对工作结构赋值
*/
#define INIT_WORK(_work, _func, _data)				\
	do {							\
		INIT_LIST_HEAD(&(_work)->entry);		\
		(_work)->pending = 0;				\
		PREPARE_WORK((_work), (_func), (_data));	\
		init_timer(&(_work)->timer);			\
	} while (0)

extern struct workqueue_struct *__create_workqueue(const char *name,
						    int singlethread);
/*
*	接收一个字符串作为参数,返回新创建工作队列的workqueue_struct描述符地址
*	还创建n个工作者线程(n是当前系统中有效运行CPU的个数)
*	并根据传递给函数的字符串为工作者线程命名
*/
#define create_workqueue(name) __create_workqueue((name), 0)
/*只创建一个工作者线程*/
#define create_singlethread_workqueue(name) __create_workqueue((name), 1)

/*撤销工作队列*/
extern void destroy_workqueue(struct workqueue_struct *wq);

extern int FASTCALL(queue_work(struct workqueue_struct *wq, struct work_struct *work));
extern int FASTCALL(queue_delayed_work(struct workqueue_struct *wq, struct work_struct *work, unsigned long delay));
extern void FASTCALL(flush_workqueue(struct workqueue_struct *wq));

extern int FASTCALL(schedule_work(struct work_struct *work));
extern int FASTCALL(schedule_delayed_work(struct work_struct *work, unsigned long delay));

extern int schedule_delayed_work_on(int cpu, struct work_struct *work, unsigned long delay);
extern void flush_scheduled_work(void);
extern int current_is_keventd(void);
extern int keventd_up(void);

extern void init_workqueues(void);

/*
 * Kill off a pending schedule_delayed_work().  Note that the work callback
 * function may still be running on return from cancel_delayed_work().  Run
 * flush_scheduled_work() to wait on it.
 */
static inline int cancel_delayed_work(struct work_struct *work)
{
	int ret;

	ret = del_timer_sync(&work->timer);
	if (ret)
		clear_bit(0, &work->pending);
	return ret;
}

#endif
