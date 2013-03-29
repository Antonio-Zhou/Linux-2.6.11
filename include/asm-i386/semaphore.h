#ifndef _I386_SEMAPHORE_H
#define _I386_SEMAPHORE_H

#include <linux/linkage.h>

#ifdef __KERNEL__

/*
 * SMP- and interrupt-safe semaphores..
 *
 * (C) Copyright 1996 Linus Torvalds
 *
 * Modified 1996-12-23 by Dave Grothe <dave@gcom.com> to fix bugs in
 *                     the original code and to make semaphore waits
 *                     interruptible so that processes waiting on
 *                     semaphores can be killed.
 * Modified 1999-02-14 by Andrea Arcangeli, split the sched.c helper
 *		       functions in asm/sempahore-helper.h while fixing a
 *		       potential and subtle race discovered by Ulrich Schmid
 *		       in down_interruptible(). Since I started to play here I
 *		       also implemented the `trylock' semaphore operation.
 *          1999-07-02 Artur Skawina <skawina@geocities.com>
 *                     Optimized "0(ecx)" -> "(ecx)" (the assembler does not
 *                     do this). Changed calling sequences from push/jmp to
 *                     traditional call/ret.
 * Modified 2001-01-01 Andreas Franck <afranck@gmx.de>
 *		       Some hacks to ensure compatibility with recent
 *		       GCC snapshots, to avoid stack corruption when compiling
 *		       with -fomit-frame-pointer. It's not sure if this will
 *		       be fixed in GCC, as our previous implementation was a
 *		       bit dubious.
 *
 * If you would like to see an analysis of this implementation, please
 * ftp to gcom.com and download the file
 * /pub/linux/src/semaphore/semaphore-2.0.24.tar.gz.
 *
 */

#include <asm/system.h>
#include <asm/atomic.h>
#include <linux/wait.h>
#include <linux/rwsem.h>

struct semaphore {
	/*
	*	>0:	资源是空闲的,即是现在可以使用的
	*	=0:	信号量是忙的,但没有进程等待这个被保护的资源
	*	<0:	资源是不可用的,并至少有一个进程等待资源
	*/
	atomic_t count;
	/*一个标志,表示是否有一些进程在信号量上睡眠.*/
	int sleepers;
	/*
	*	等待队列链表的地址,当前等待资源的所有睡眠进程都放在这个链表中.
	*	count >=0, 等待队列为空
	*/
	wait_queue_head_t wait;
};


#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.count		= ATOMIC_INIT(n),				\
	.sleepers	= 0,						\
	.wait		= __WAIT_QUEUE_HEAD_INITIALIZER((name).wait)	\
}

#define __MUTEX_INITIALIZER(name) \
	__SEMAPHORE_INITIALIZER(name,1)

#define __DECLARE_SEMAPHORE_GENERIC(name,count) \
	struct semaphore name = __SEMAPHORE_INITIALIZER(name,count)

#define DECLARE_MUTEX(name) __DECLARE_SEMAPHORE_GENERIC(name,1)
#define DECLARE_MUTEX_LOCKED(name) __DECLARE_SEMAPHORE_GENERIC(name,0)

static inline void sema_init (struct semaphore *sem, int val)
{
/*
 *	*sem = (struct semaphore)__SEMAPHORE_INITIALIZER((*sem),val);
 *
 * i'd rather use the more flexible initialization above, but sadly
 * GCC 2.7.2.3 emits a bogus warning. EGCS doesn't. Oh well.
 */
	atomic_set(&sem->count, val);
	sem->sleepers = 0;
	init_waitqueue_head(&sem->wait);
}

/*初始化信号量,互斥访问的资源空闲*/
static inline void init_MUTEX (struct semaphore *sem)
{
	sema_init(sem, 1);
}

/*对信号量进行初始化的进程当前互斥访问的资源忙*/
static inline void init_MUTEX_LOCKED (struct semaphore *sem)
{
	sema_init(sem, 0);
}

fastcall void __down_failed(void /* special register calling convention */);
fastcall int  __down_failed_interruptible(void  /* params in registers */);
fastcall int  __down_failed_trylock(void  /* params in registers */);
fastcall void __up_wakeup(void /* special register calling convention */);

fastcall void __down(struct semaphore * sem);
fastcall int  __down_interruptible(struct semaphore * sem);
fastcall int  __down_trylock(struct semaphore * sem);
fastcall void __up(struct semaphore * sem);

/*
 * This is ugly, but we want the default case to fall through.
 * "__down_failed" is a special asm handler that calls the C
 * routine that actually waits. See arch/i386/kernel/semaphore.c
 */

/*
*	只有异常处理程序,特别是系统调用服务例程,才能调用down()函数
*	中断处理函数不必调用down(),
*/
static inline void down(struct semaphore * sem)
{
	might_sleep();
	__asm__ __volatile__(
		"# atomic down operation\n\t"
		LOCK "decl %0\n\t"     /* --sem->count */
		"js 2f\n"
		"1:\n"
		LOCK_SECTION_START("")
		"2:\tlea %0,%%eax\n\t"
		"call __down_failed\n\t"
		"jmp 1b\n"
		LOCK_SECTION_END
		:"=m" (sem->count)
		:
		:"memory","ax");
}

/*
 * Interruptible try to acquire a semaphore.  If we obtained
 * it, return zero.  If we were interrupted, returns -EINTR
 */

/*
*	广泛的应用在设备驱动程序中,
*	如果进程接收了一个信号但在信号量上被阻塞,就允许进程放弃down()

*/
static inline int down_interruptible(struct semaphore * sem)
{
	int result;

	might_sleep();
	__asm__ __volatile__(
		"# atomic interruptible down operation\n\t"
		LOCK "decl %1\n\t"     /* --sem->count */
		"js 2f\n\t"
		"xorl %0,%0\n"
		"1:\n"
		LOCK_SECTION_START("")
		"2:\tlea %1,%%eax\n\t"
		"call __down_failed_interruptible\n\t"
		"jmp 1b\n"
		LOCK_SECTION_END
		:"=a" (result), "=m" (sem->count)
		:
		:"memory");
	return result;
}

/*
 * Non-blockingly attempt to down() a semaphore.
 * Returns zero if we acquired it
 */

/*
*	异步函数安全的使用
*	在资源繁忙时,该函数会立即返回,而不是让进程去睡眠
*/
static inline int down_trylock(struct semaphore * sem)
{
	int result;

	__asm__ __volatile__(
		"# atomic interruptible down operation\n\t"
		LOCK "decl %1\n\t"     /* --sem->count */
		"js 2f\n\t"
		"xorl %0,%0\n"
		"1:\n"
		LOCK_SECTION_START("")
		"2:\tlea %1,%%eax\n\t"
		"call __down_failed_trylock\n\t"
		"jmp 1b\n"
		LOCK_SECTION_END
		:"=a" (result), "=m" (sem->count)
		:
		:"memory");
	return result;
}

/*
 * Note! This is subtle. We jump to wake people up only if
 * the semaphore was negative (== somebody was waiting on it).
 * The default case (no contention) will result in NO
 * jumps for both down() and up().
 */
 /*
 *	获取信号量
 *	增加*sem信号量count字段的值
 *	count的增加和jump指令所测试的标志的设置都必须原子地执行
*/
static inline void up(struct semaphore * sem)
{
	__asm__ __volatile__(
		"# atomic up operation\n\t"
		LOCK "incl %0\n\t"     /* ++sem->count */
		"jle 2f\n"
		"1:\n"
		LOCK_SECTION_START("")
		"2:\tlea %0,%%eax\n\t"
		"call __up_wakeup\n\t"
		"jmp 1b\n"
		LOCK_SECTION_END
		".subsection 0\n"
		:"=m" (sem->count)
		:
		:"memory","ax");
}

#endif
#endif
