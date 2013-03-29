#ifndef _ASMi386_TIMER_H
#define _ASMi386_TIMER_H
#include <linux/init.h>

/**
 * struct timer_ops - used to define a timer source
 *
 * @name: name of the timer.
 * @init: Probes and initializes the timer. Takes clock= override 
 *        string as an argument. Returns 0 on success, anything else
 *        on failure.
 * @mark_offset: called by the timer interrupt.
 * @get_offset:  called by gettimeofday(). Returns the number of microseconds
 *               since the last timer interupt.
 * @monotonic_clock: returns the number of nanoseconds since the init of the
 *                   timer.
 * @delay: delays this many clock cycles.
 */

/*定时器对象*/
struct timer_opts {
	char* name;				/*标识一个定时器源的一个字符串*/
	/*
	*	记录上一个节拍的准确时间,由时钟中断处理程序调用
	*	由时钟中断处理程序调用,并以适当的数据结构记录每个节拍到来时的准确时间
	*/
	void (*mark_offset)(void);	
	unsigned long (*get_offset)(void);	/*返回自上一个节拍开始所经过的时间*/
	unsigned long long (*monotonic_clock)(void);		/*返回自内核初始化开始锁经过的纳秒数*/
	void (*delay)(unsigned long);	/*等待指定数目的"循环"*/
};

struct init_timer_opts {
	int (*init)(char *override);
	struct timer_opts *opts;
};

#define TICK_SIZE (tick_nsec / 1000)

extern struct timer_opts* __init select_timer(void);
extern void clock_fallback(void);
void setup_pit_timer(void);

/* Modifiers for buggy PIT handling */

extern int pit_latch_buggy;

extern struct timer_opts *cur_timer;
extern int timer_ack;

/* list of externed timers */
extern struct timer_opts timer_none;
extern struct timer_opts timer_pit;
extern struct init_timer_opts timer_pit_init;
extern struct init_timer_opts timer_tsc_init;
#ifdef CONFIG_X86_CYCLONE_TIMER
extern struct init_timer_opts timer_cyclone_init;
#endif

extern unsigned long calibrate_tsc(void);
extern void init_cpu_khz(void);
#ifdef CONFIG_HPET_TIMER
extern struct init_timer_opts timer_hpet_init;
extern unsigned long calibrate_tsc_hpet(unsigned long *tsc_hpet_quotient_ptr);
#endif

#ifdef CONFIG_X86_PM_TIMER
extern struct init_timer_opts timer_pmtmr_init;
#endif
#endif
