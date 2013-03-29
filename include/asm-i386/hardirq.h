#ifndef __ASM_HARDIRQ_H
#define __ASM_HARDIRQ_H

#include <linux/config.h>
#include <linux/threads.h>
#include <linux/irq.h>

typedef struct {
	unsigned int __softirq_pending;	/*表示挂起的软中断,为一组标志*/
	unsigned long idle_timestamp;		/*CPU	变为空闲的时间(只是在CPU正空闲的时候才有意义)*/
	unsigned int __nmi_count;	/* arch dependent */	/*NMI中断发生的次数*/
	unsigned int apic_timer_irqs;	/* arch dependent */	/*本地APIC 时钟中断发生的次数*/
} ____cacheline_aligned irq_cpustat_t;

#include <linux/irq_cpustat.h>	/* Standard mappings for irq_cpustat_t above */

void ack_bad_irq(unsigned int irq);

#endif /* __ASM_HARDIRQ_H */
