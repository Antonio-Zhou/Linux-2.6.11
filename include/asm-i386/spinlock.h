#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#include <asm/atomic.h>
#include <asm/rwlock.h>
#include <asm/page.h>
#include <linux/config.h>
#include <linux/compiler.h>

asmlinkage int printk(const char * fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

/*
 * Your basic SMP spinlocks, allowing only a single CPU anywhere
 */

typedef struct {
	volatile unsigned int slock;		/*表示自旋锁的状态.==1表示"未加锁"状态, <=0表示"加锁"状态*/
#ifdef CONFIG_DEBUG_SPINLOCK
	unsigned magic;
#endif
#ifdef CONFIG_PREEMPT
	unsigned int break_lock;		/*进程正在忙等自旋锁(只在内核支持SMP和内核抢占的情况下使用该标志)*/
#endif
} spinlock_t;

#define SPINLOCK_MAGIC	0xdead4ead

#ifdef CONFIG_DEBUG_SPINLOCK
#define SPINLOCK_MAGIC_INIT	, SPINLOCK_MAGIC
#else
#define SPINLOCK_MAGIC_INIT	/* */
#endif

#define SPIN_LOCK_UNLOCKED (spinlock_t) { 1 SPINLOCK_MAGIC_INIT }

/*把自旋锁置为1(未锁)*/
#define spin_lock_init(x)	do { *(x) = SPIN_LOCK_UNLOCKED; } while(0)

/*
 * Simple spin lock operations.  There are two variants, one clears IRQ's
 * on the local processor, one does not.
 *
 * We make no fairness assumptions. They have a cost.
 */

/*如果 自旋锁被置为1(未锁),返回0,否则,返回1*/
#define spin_is_locked(x)	(*(volatile signed char *)(&(x)->slock) <= 0)
/*等待,直到自旋锁变为1*/
#define spin_unlock_wait(x)	do { barrier(); } while(spin_is_locked(x))

#define spin_lock_string \
	"\n1:\t" \
	"lock ; decb %0\n\t" \
	"jns 3f\n" \
	"2:\t" \
	"rep;nop\n\t" \
	"cmpb $0,%0\n\t" \
	"jle 2b\n\t" \
	"jmp 1b\n" \
	"3:\n\t"

#define spin_lock_string_flags \
	"\n1:\t" \
	"lock ; decb %0\n\t" \
	"jns 4f\n\t" \
	"2:\t" \
	"testl $0x200, %1\n\t" \
	"jz 3f\n\t" \
	"sti\n\t" \
	"3:\t" \
	"rep;nop\n\t" \
	"cmpb $0, %0\n\t" \
	"jle 3b\n\t" \
	"cli\n\t" \
	"jmp 1b\n" \
	"4:\n\t"

/*
 * This works. Despite all the confusion.
 * (except on PPro SMP or if we are using OOSTORE)
 * (PPro errata 66, 92)
 */

#if !defined(CONFIG_X86_OOSTORE) && !defined(CONFIG_X86_PPRO_FENCE)

#define spin_unlock_string \
	"movb $1,%0" \
		:"=m" (lock->slock) : : "memory"


static inline void _raw_spin_unlock(spinlock_t *lock)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(lock->magic != SPINLOCK_MAGIC);
	BUG_ON(!spin_is_locked(lock));
#endif
	__asm__ __volatile__(
		spin_unlock_string
	);
}

#else

#define spin_unlock_string \
	"xchgb %b0, %1" \
		:"=q" (oldval), "=m" (lock->slock) \
		:"0" (oldval) : "memory"

static inline void _raw_spin_unlock(spinlock_t *lock)
{
	char oldval = 1;
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(lock->magic != SPINLOCK_MAGIC);
	BUG_ON(!spin_is_locked(lock));
#endif
	__asm__ __volatile__(
		spin_unlock_string
	);
}

#endif

static inline int _raw_spin_trylock(spinlock_t *lock)
{
	char oldval;
	__asm__ __volatile__(
		"xchgb %b0,%1"
		:"=q" (oldval), "=m" (lock->slock)
		:"0" (0) : "memory");
	return oldval > 0;
}

static inline void _raw_spin_lock(spinlock_t *lock)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	if (unlikely(lock->magic != SPINLOCK_MAGIC)) {
		printk("eip: %p\n", __builtin_return_address(0));
		BUG();
	}
#endif
	__asm__ __volatile__(
		spin_lock_string
		:"=m" (lock->slock) : : "memory");
}

static inline void _raw_spin_lock_flags (spinlock_t *lock, unsigned long flags)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	if (unlikely(lock->magic != SPINLOCK_MAGIC)) {
		printk("eip: %p\n", __builtin_return_address(0));
		BUG();
	}
#endif
	__asm__ __volatile__(
		spin_lock_string_flags
		:"=m" (lock->slock) : "r" (flags) : "memory");
}

/*
 * Read-write spinlocks, allowing multiple readers
 * but only one writer.
 *
 * NOTE! it is quite common to have readers in interrupts
 * but no interrupt writers. For those circumstances we
 * can "mix" irq-safe locks - any writer needs to get a
 * irq-safe write-lock, but readers can get non-irqsafe
 * read-locks.
 */
typedef struct {
	/*
	*	32位字段,分为下面两个部分
	*	24位计数器,表示对受保护的数据结构并发的进行读操作的内核控制路径的数目
	*	这个计数器的补码放在这个字段的0-23位
	*	"未锁"标志字段,当没有内核控制路径在读或写时设置该位,否则清0。这个"未锁"标志放在lock字段的第24位
	*	lock == 0x01000000, 自旋锁为空
	*	lock == 0x00000000, 写者已经获得自旋锁
	*	lock == 0x00ffffff,0x00fffffe等,一个或者多个进程获取了自旋锁
	*/
	volatile unsigned int lock;
#ifdef CONFIG_DEBUG_SPINLOCK
	unsigned magic;
#endif
#ifdef CONFIG_PREEMPT
	unsigned int break_lock;
#endif
} rwlock_t;

#define RWLOCK_MAGIC	0xdeaf1eed

#ifdef CONFIG_DEBUG_SPINLOCK
#define RWLOCK_MAGIC_INIT	, RWLOCK_MAGIC
#else
#define RWLOCK_MAGIC_INIT	/* */
#endif

/*RW_LOCK_BIAS==0x01000000*/
#define RW_LOCK_UNLOCKED (rwlock_t) { RW_LOCK_BIAS RWLOCK_MAGIC_INIT }

#define rwlock_init(x)	do { *(x) = RW_LOCK_UNLOCKED; } while(0)

/**
 * read_can_lock - would read_trylock() succeed?
 * @lock: the rwlock in question.
 */
#define read_can_lock(x) ((int)(x)->lock > 0)

/**
 * write_can_lock - would write_trylock() succeed?
 * @lock: the rwlock in question.
 */
#define write_can_lock(x) ((x)->lock == RW_LOCK_BIAS)

/*
 * On x86, we implement read-write locks as a 32-bit counter
 * with the high bit (sign) being the "contended" bit.
 *
 * The inline assembly is non-obvious. Think about it.
 *
 * Changed to use the same technique as rw semaphores.  See
 * semaphore.h for details.  -ben
 */
/* the spinlock helpers are in arch/i386/kernel/semaphore.c */

static inline void _raw_read_lock(rwlock_t *rw)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(rw->magic != RWLOCK_MAGIC);
#endif
	__build_read_lock(rw, "__read_lock_failed");
}

static inline void _raw_write_lock(rwlock_t *rw)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	BUG_ON(rw->magic != RWLOCK_MAGIC);
#endif
	__build_write_lock(rw, "__write_lock_failed");
}

#define _raw_read_unlock(rw)		asm volatile("lock ; incl %0" :"=m" ((rw)->lock) : : "memory")
#define _raw_write_unlock(rw)	asm volatile("lock ; addl $" RW_LOCK_BIAS_STR ",%0":"=m" ((rw)->lock) : : "memory")

/*计数器lock字段的操作时原子的,但是整个函数的访问不是原子的*/
static inline int _raw_read_trylock(rwlock_t *lock)
{
	atomic_t *count = (atomic_t *)lock;
	atomic_dec(count);
	/*此处if判断和return之间，计数器的值就有可能改变*/
	if (atomic_read(count) >= 0)
		return 1;
	atomic_inc(count);
	return 0;
}

static inline int _raw_write_trylock(rwlock_t *lock)
{
	atomic_t *count = (atomic_t *)lock;
	/*
	*	从count中减去0x01000000,从而清除未上锁标志(第24位)
	*	==0(没有读者),获取锁并返回1
	*/
	if (atomic_sub_and_test(RW_LOCK_BIAS, count))
		return 1;
	atomic_add(RW_LOCK_BIAS, count);
	return 0;
}

#endif /* __ASM_SPINLOCK_H */
