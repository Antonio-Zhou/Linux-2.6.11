#ifndef __irq_h
#define __irq_h

/*
 * Please do not include this file in generic code.  There is currently
 * no requirement for any architecture to implement anything held
 * within this file.
 *
 * Thanks. --rmk
 */

#include <linux/config.h>

#if !defined(CONFIG_ARCH_S390)

#include <linux/linkage.h>
#include <linux/cache.h>
#include <linux/spinlock.h>
#include <linux/cpumask.h>

#include <asm/irq.h>
#include <asm/ptrace.h>

/*
 * IRQ line status.
 */
#define IRQ_INPROGRESS	1	/* IRQ handler active - do not enter! */	/*IRQ的一个处理程序正在执行*/
#define IRQ_DISABLED	2	/* IRQ disabled - do not enter! */		/*由一个设备驱动程序故意地禁用IRQ线*/
#define IRQ_PENDING	4	/* IRQ pending - replay on enable */			/*一个IRQ已经出现在线上,它的出现也已对PIC做出应答,但是内核还没有对它提供服务*/
#define IRQ_REPLAY	8	/* IRQ has been replayed but not acked yet */	/*IRQ线已经被禁用,但是前一个出现的IRQ还没有对PIC做出应答*/
#define IRQ_AUTODETECT	16	/* IRQ is being autodetected */			/*内核在执行硬件设备探测时使用IRQ线*/
#define IRQ_WAITING	32	/* IRQ not yet seen - for autodetection */		/*内核在执行硬件设备探测时使用IRQ线,此外,相应的中断还没有产生*/
#define IRQ_LEVEL	64	/* IRQ level triggered */
#define IRQ_MASKED	128	/* IRQ masked - shouldn't be seen again */
#define IRQ_PER_CPU	256	/* IRQ is per CPU */

/*
 * Interrupt controller descriptor. This is all we need
 * to describe about the low-level hardware. 
 */

/*PIC 对象*/
struct hw_interrupt_type {
	const char * typename;				/*PIC 名称*/
	unsigned int (*startup)(unsigned int irq);	/*启动芯片的IRQ线*/
	void (*shutdown)(unsigned int irq);		/*关闭芯片的IRQ线*/
	void (*enable)(unsigned int irq);			/*启用芯片的IRQ线*/
	void (*disable)(unsigned int irq);		/*禁用芯片的IRQ线*/
	void (*ack)(unsigned int irq);			/*通过向设备的I/O端口发送适当的字节来应答所接收的IRQ*/
	void (*end)(unsigned int irq);			/*IRQ的中断处理程序结束时调用*/
	/*多处理器系统中以声明特定IRQ所在CPU的"亲和力"
	* 那些CPU被启用来处理特定的IRQ
	*/
	void (*set_affinity)(unsigned int irq, cpumask_t dest);
};

typedef struct hw_interrupt_type  hw_irq_controller;

/*
 * This is the "IRQ descriptor", which contains various information
 * about the irq, including what kind of hardware handling it has,
 * whether it is disabled etc etc.
 *
 * Pad this out to 32 bytes for cache and indexing reasons.
 */
/**/

typedef struct irq_desc {
	hw_irq_controller *handler;		/*指向PIC 对象,它服务于IRQ线*/
	void *handler_data;			/*指向PIC 方法所使用的数据*/
	struct irqaction *action;	/* IRQ action list */	/*标识当出现IRQ时要调用的中断服务例程,指向IRQ的第一个元素*/
	unsigned int status;		/* IRQ status */		/*描述IRQ线状态的一组标志*/
	unsigned int depth;		/* nested irq disables */	/*如果IRQ总线被激活,则显示0,如果被禁止了不止一次,就显示一个正数*/
	unsigned int irq_count;		/* For detecting broken interrupts */	/*中断计数器,统计IRQ总线上发生中断的次数*/
	unsigned int irqs_unhandled;	/*对在IRQ线上发生终端的的次数*/
	spinlock_t lock;				/*用于串行访问IRQ描述符和PIC的自旋锁*/
} ____cacheline_aligned irq_desc_t;

extern irq_desc_t irq_desc [NR_IRQS];

#include <asm/hw_irq.h> /* the arch dependent stuff */

extern int setup_irq(unsigned int irq, struct irqaction * new);

#ifdef CONFIG_GENERIC_HARDIRQS
extern cpumask_t irq_affinity[NR_IRQS];
extern int no_irq_affinity;
extern int noirqdebug_setup(char *str);

extern fastcall int handle_IRQ_event(unsigned int irq, struct pt_regs *regs,
				       struct irqaction *action);
extern fastcall unsigned int __do_IRQ(unsigned int irq, struct pt_regs *regs);
extern void note_interrupt(unsigned int irq, irq_desc_t *desc, int action_ret);
extern void report_bad_irq(unsigned int irq, irq_desc_t *desc, int action_ret);
extern int can_request_irq(unsigned int irq, unsigned long irqflags);

extern void init_irq_proc(void);
#endif

extern hw_irq_controller no_irq_type;  /* needed in every arch ? */

#endif

#endif /* __irq_h */
