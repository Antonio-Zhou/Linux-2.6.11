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
#define IRQ_INPROGRESS	1	/* IRQ handler active - do not enter! */	/*IRQ��һ�������������ִ��*/
#define IRQ_DISABLED	2	/* IRQ disabled - do not enter! */		/*��һ���豸�����������ؽ���IRQ��*/
#define IRQ_PENDING	4	/* IRQ pending - replay on enable */			/*һ��IRQ�Ѿ�����������,���ĳ���Ҳ�Ѷ�PIC����Ӧ��,�����ں˻�û�ж����ṩ����*/
#define IRQ_REPLAY	8	/* IRQ has been replayed but not acked yet */	/*IRQ���Ѿ�������,����ǰһ�����ֵ�IRQ��û�ж�PIC����Ӧ��*/
#define IRQ_AUTODETECT	16	/* IRQ is being autodetected */			/*�ں���ִ��Ӳ���豸̽��ʱʹ��IRQ��*/
#define IRQ_WAITING	32	/* IRQ not yet seen - for autodetection */		/*�ں���ִ��Ӳ���豸̽��ʱʹ��IRQ��,����,��Ӧ���жϻ�û�в���*/
#define IRQ_LEVEL	64	/* IRQ level triggered */
#define IRQ_MASKED	128	/* IRQ masked - shouldn't be seen again */
#define IRQ_PER_CPU	256	/* IRQ is per CPU */

/*
 * Interrupt controller descriptor. This is all we need
 * to describe about the low-level hardware. 
 */

/*PIC ����*/
struct hw_interrupt_type {
	const char * typename;				/*PIC ����*/
	unsigned int (*startup)(unsigned int irq);	/*����оƬ��IRQ��*/
	void (*shutdown)(unsigned int irq);		/*�ر�оƬ��IRQ��*/
	void (*enable)(unsigned int irq);			/*����оƬ��IRQ��*/
	void (*disable)(unsigned int irq);		/*����оƬ��IRQ��*/
	void (*ack)(unsigned int irq);			/*ͨ�����豸��I/O�˿ڷ����ʵ����ֽ���Ӧ�������յ�IRQ*/
	void (*end)(unsigned int irq);			/*IRQ���жϴ���������ʱ����*/
	/*�ദ����ϵͳ���������ض�IRQ����CPU��"�׺���"
	* ��ЩCPU�������������ض���IRQ
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
	hw_irq_controller *handler;		/*ָ��PIC ����,��������IRQ��*/
	void *handler_data;			/*ָ��PIC ������ʹ�õ�����*/
	struct irqaction *action;	/* IRQ action list */	/*��ʶ������IRQʱҪ���õ��жϷ�������,ָ��IRQ�ĵ�һ��Ԫ��*/
	unsigned int status;		/* IRQ status */		/*����IRQ��״̬��һ���־*/
	unsigned int depth;		/* nested irq disables */	/*���IRQ���߱�����,����ʾ0,�������ֹ�˲�ֹһ��,����ʾһ������*/
	unsigned int irq_count;		/* For detecting broken interrupts */	/*�жϼ�����,ͳ��IRQ�����Ϸ����жϵĴ���*/
	unsigned int irqs_unhandled;	/*����IRQ���Ϸ����ն˵ĵĴ���*/
	spinlock_t lock;				/*���ڴ��з���IRQ��������PIC��������*/
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
