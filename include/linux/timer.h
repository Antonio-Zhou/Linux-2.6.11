#ifndef _LINUX_TIMER_H
#define _LINUX_TIMER_H

#include <linux/config.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/stddef.h>

struct tvec_t_base_s;

struct timer_list {
	/*
	*	将定时器插入双向循环链表队列中,
	*	该链表根据定时器expires字段分组存放
	*/
	struct list_head entry;
	/*
	*	定时器到期时间,用节拍数表示,
	*	其值为系统启动以来所经过的节拍数
	*	当expires <= jiffies,说明计时器到期或终止
	*/
	unsigned long expires;

	spinlock_t lock;
	unsigned long magic;

	void (*function)(unsigned long);		/*定时器到期时执行函数的地址*/
	/*
	*	传递给定时器函数的参数
	*	由于data字段,可以定义一个单独的通用函数来处理多个设备驱动程序的超时问题
	*	在data字段可以存放设备ID,或其他有意义的数据,定时器函数依此来区分不同的设备
	*/
	unsigned long data;				

	struct tvec_t_base_s *base;
};

#define TIMER_MAGIC	0x4b87ad6e

#define TIMER_INITIALIZER(_function, _expires, _data) {		\
		.function = (_function),			\
		.expires = (_expires),				\
		.data = (_data),				\
		.base = NULL,					\
		.magic = TIMER_MAGIC,				\
		.lock = SPIN_LOCK_UNLOCKED,			\
	}

/***
 * init_timer - initialize a timer.
 * @timer: the timer to be initialized
 *
 * init_timer() must be done to a timer prior calling *any* of the
 * other timer functions.
 */
static inline void init_timer(struct timer_list * timer)
{
	timer->base = NULL;
	timer->magic = TIMER_MAGIC;
	spin_lock_init(&timer->lock);
}

/***
 * timer_pending - is a timer pending?
 * @timer: the timer in question
 *
 * timer_pending will tell whether a given timer is currently pending,
 * or not. Callers must ensure serialization wrt. other operations done
 * to this timer, eg. interrupt contexts, or other CPUs on SMP.
 *
 * return value: 1 if the timer is pending, 0 if not.
 */
static inline int timer_pending(const struct timer_list * timer)
{
	return timer->base != NULL;
}

extern void add_timer_on(struct timer_list *timer, int cpu);
extern int del_timer(struct timer_list * timer);
extern int __mod_timer(struct timer_list *timer, unsigned long expires);
/*动态定时器已经在链表中,更新expires,也能将对象插入到合适的链表中*/
extern int mod_timer(struct timer_list *timer, unsigned long expires);

extern unsigned long next_timer_interrupt(void);

/***
 * add_timer - start a timer
 * @timer: the timer to be added
 *
 * The kernel will do a ->function(->data) callback from the
 * timer interrupt at the ->expired point in the future. The
 * current time is 'jiffies'.
 *
 * The timer's ->expired, ->function (and if the handler uses it, ->data)
 * fields must be set prior calling this function.
 *
 * Timers with an ->expired field in the past will be executed in the next
 * timer tick.
 */

/*把定时器插入到适合的链表中(根据expires)*/
static inline void add_timer(struct timer_list * timer)
{
	__mod_timer(timer, timer->expires);
}

#ifdef CONFIG_SMP
  extern int del_timer_sync(struct timer_list *timer);
  extern int del_singleshot_timer_sync(struct timer_list *timer);
#else
# define del_timer_sync(t) del_timer(t)
# define del_singleshot_timer_sync(t) del_timer(t)
#endif

extern void init_timers(void);
extern void run_local_timers(void);
extern void it_real_fn(unsigned long);

#endif
