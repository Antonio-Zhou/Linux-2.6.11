/*
 *	linux/arch/i386/kernel/irq.c
 *
 *	Copyright (C) 1992, 1998 Linus Torvalds, Ingo Molnar
 *
 * This file contains the lowest level x86-specific interrupt
 * entry, irq-stacks and irq statistics code. All the remaining
 * irq logic is done by the generic kernel/irq/ code and
 * by the x86-specific irq controller code. (e.g. i8259.c and
 * io_apic.c.)
 */

#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>

#ifndef CONFIG_X86_LOCAL_APIC
/*
 * 'what should we do if we get a hw irq event on an illegal vector'.
 * each architecture has to answer this themselves.
 */
void ack_bad_irq(unsigned int irq)
{
	printk("unexpected IRQ trap at vector %02x\n", irq);
}
#endif

#ifdef CONFIG_4KSTACKS
/*
 * per-CPU IRQ handling contexts (thread information and stack)
 */
 /*
 *每个CPU的中断上下文
 *thread_info放在页的底部，栈使用其余的内存空间
*thread_info与CPU相关联
*/
union irq_ctx {
	struct thread_info      tinfo;
	u32                     stack[THREAD_SIZE/sizeof(u32)];
};

/*所有硬中断请求*/
static union irq_ctx *hardirq_ctx[NR_CPUS];
 /*所有软中断请求*/
static union irq_ctx *softirq_ctx[NR_CPUS];
#endif

/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
fastcall unsigned int do_IRQ(struct pt_regs *regs)
{	
	/* high bits used in ret_from_ code */
	int irq = regs->orig_eax & 0xff;
#ifdef CONFIG_4KSTACKS
	union irq_ctx *curctx, *irqctx;
	u32 *isp;
#endif
/*
*	使表示中断处理程序嵌套数量的计数器递增
*/
	irq_enter();
#ifdef CONFIG_DEBUG_STACKOVERFLOW
	/* Debugging check for stack overflow: is there less than 1KB free? */
	{
		long esp;

		__asm__ __volatile__("andl %%esp,%0" :
					"=r" (esp) : "0" (THREAD_SIZE - 1));
		if (unlikely(esp < (sizeof(struct thread_info) + STACK_WARN))) {
			printk("do_IRQ: stack overflow: %ld\n",
				esp - sizeof(struct thread_info));
			dump_stack();
		}
	}
#endif

/*thread_info结构的大小为4KB,函数切换到硬中断请求栈*/
#ifdef CONFIG_4KSTACKS

	/*内核栈(地址在esp中)相连的thread_info描述符的地址*/
	curctx = (union irq_ctx *) current_thread_info();
	/*hardirq_ctx[smp_processor_id()]的地址*/
	irqctx = hardirq_ctx[smp_processor_id()];

	/*
	 * this is where we switch to the IRQ stack. However, if we are
	 * already using the IRQ stack (because we interrupted a hardirq
	 * handler) we can't do that and just have to keep using the
	 * current stack (which is the irq stack already after all)
	 */
	/***********没看懂!!!!!!在书的P180***********/
	if (curctx != irqctx) {
		int arg1, arg2, ebx;

		/* build the stack frame on the IRQ stack */
		/*切换内核栈*/
		isp = (u32*) ((char*)irqctx + sizeof(*irqctx));
		/*
		*	保存当前进程描述符指针
		*	完成这操作就能在内核使用硬中断请求栈时使当前宏按预先的期望工作
		*/
		irqctx->tinfo.task = curctx->tinfo.task;
		/*
		*	esp栈指针寄存器的当前值存入本地CPU的irq_ctx的tinfo.previous_esp 
		*	仅当为内核oop准备函数调用跟踪时使用该字段
		*/
		irqctx->tinfo.previous_esp = current_stack_pointer;

		asm volatile(
			/*
			*	把本地CPU硬中断请求栈的栈顶(值等于hardirq_ctx[smp_processor_id()]+4096)装入esp寄存器
			*	以前esp的值存入ebx寄存器
			*	成功则说明已经切换到硬中断请求栈
			*/
			"       xchgl   %%ebx,%%esp      \n"
			"       call    __do_IRQ         \n"
			/*把ebx寄存器中的原始指针拷贝到esp,从而回到以前在用的栈*/
			"       movl   %%ebx,%%esp      \n"
			: "=a" (arg1), "=d" (arg2), "=b" (ebx)
			:  "0" (irq),   "1" (regs),  "2" (isp)
			: "memory", "cc", "ecx"
		);
	 /*
	 *内核已经在使用硬中断请求栈
	 *这种情况发生在内核处理另外一个中断时又产生了中断请求的时候
	 */
	} else	
#endif
		__do_IRQ(irq, regs);

	irq_exit();

	return 1;
}

#ifdef CONFIG_4KSTACKS

/*
 * These should really be __section__(".bss.page_aligned") as well, but
 * gcc's 3.0 and earlier don't handle that correctly.
 */
static char softirq_stack[NR_CPUS * THREAD_SIZE]
		__attribute__((__aligned__(THREAD_SIZE)));

static char hardirq_stack[NR_CPUS * THREAD_SIZE]
		__attribute__((__aligned__(THREAD_SIZE)));

/*
 * allocate per-cpu stacks for hardirq and for softirq processing
 */
void irq_ctx_init(int cpu)
{
	union irq_ctx *irqctx;

	if (hardirq_ctx[cpu])
		return;

	irqctx = (union irq_ctx*) &hardirq_stack[cpu*THREAD_SIZE];
	irqctx->tinfo.task              = NULL;
	irqctx->tinfo.exec_domain       = NULL;
	irqctx->tinfo.cpu               = cpu;
	irqctx->tinfo.preempt_count     = HARDIRQ_OFFSET;
	irqctx->tinfo.addr_limit        = MAKE_MM_SEG(0);

	hardirq_ctx[cpu] = irqctx;

	irqctx = (union irq_ctx*) &softirq_stack[cpu*THREAD_SIZE];
	irqctx->tinfo.task              = NULL;
	irqctx->tinfo.exec_domain       = NULL;
	irqctx->tinfo.cpu               = cpu;
	irqctx->tinfo.preempt_count     = SOFTIRQ_OFFSET;
	irqctx->tinfo.addr_limit        = MAKE_MM_SEG(0);

	softirq_ctx[cpu] = irqctx;

	printk("CPU %u irqstacks, hard=%p soft=%p\n",
		cpu,hardirq_ctx[cpu],softirq_ctx[cpu]);
}

extern asmlinkage void __do_softirq(void);

asmlinkage void do_softirq(void)
{
	unsigned long flags;
	struct thread_info *curctx;
	union irq_ctx *irqctx;
	u32 *isp;

	if (in_interrupt())
		return;

	local_irq_save(flags);

	if (local_softirq_pending()) {
		curctx = current_thread_info();
		irqctx = softirq_ctx[smp_processor_id()];
		irqctx->tinfo.task = curctx->task;
		irqctx->tinfo.previous_esp = current_stack_pointer;

		/* build the stack frame on the softirq stack */
		isp = (u32*) ((char*)irqctx + sizeof(*irqctx));

		asm volatile(
			"       xchgl   %%ebx,%%esp     \n"
			"       call    __do_softirq    \n"
			"       movl    %%ebx,%%esp     \n"
			: "=b"(isp)
			: "0"(isp)
			: "memory", "cc", "edx", "ecx", "eax"
		);
	}

	local_irq_restore(flags);
}

EXPORT_SYMBOL(do_softirq);
#endif

/*
 * Interrupt statistics:
 */

atomic_t irq_err_count;

/*
 * /proc/interrupts printing:
 */

int show_interrupts(struct seq_file *p, void *v)
{
	int i = *(loff_t *) v, j;
	struct irqaction * action;
	unsigned long flags;

	if (i == 0) {
		seq_printf(p, "           ");
		for (j=0; j<NR_CPUS; j++)
			if (cpu_online(j))
				seq_printf(p, "CPU%d       ",j);
		seq_putc(p, '\n');
	}

	if (i < NR_IRQS) {
		spin_lock_irqsave(&irq_desc[i].lock, flags);
		action = irq_desc[i].action;
		if (!action)
			goto skip;
		seq_printf(p, "%3d: ",i);
#ifndef CONFIG_SMP
		seq_printf(p, "%10u ", kstat_irqs(i));
#else
		for (j = 0; j < NR_CPUS; j++)
			if (cpu_online(j))
				seq_printf(p, "%10u ", kstat_cpu(j).irqs[i]);
#endif
		seq_printf(p, " %14s", irq_desc[i].handler->typename);
		seq_printf(p, "  %s", action->name);

		for (action=action->next; action; action = action->next)
			seq_printf(p, ", %s", action->name);

		seq_putc(p, '\n');
skip:
		spin_unlock_irqrestore(&irq_desc[i].lock, flags);
	} else if (i == NR_IRQS) {
		seq_printf(p, "NMI: ");
		for (j = 0; j < NR_CPUS; j++)
			if (cpu_online(j))
				seq_printf(p, "%10u ", nmi_count(j));
		seq_putc(p, '\n');
#ifdef CONFIG_X86_LOCAL_APIC
		seq_printf(p, "LOC: ");
		for (j = 0; j < NR_CPUS; j++)
			if (cpu_online(j))
				seq_printf(p, "%10u ",
					irq_stat[j].apic_timer_irqs);
		seq_putc(p, '\n');
#endif
		seq_printf(p, "ERR: %10u\n", atomic_read(&irq_err_count));
#if defined(CONFIG_X86_IO_APIC)
		seq_printf(p, "MIS: %10u\n", atomic_read(&irq_mis_count));
#endif
	}
	return 0;
}
