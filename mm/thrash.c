/*
 * mm/thrash.c
 *
 * Copyright (C) 2004, Red Hat, Inc.
 * Copyright (C) 2004, Rik van Riel <riel@redhat.com>
 * Released under the GPL, see the file COPYING for details.
 *
 * Simple token based thrashing protection, using the algorithm
 * described in:  http://www.cs.wm.edu/~sjiang/token.pdf
 */
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/swap.h>

static DEFINE_SPINLOCK(swap_token_lock);
static unsigned long swap_token_timeout;
unsigned long swap_token_check;
/*交换标记的实现形式*/
struct mm_struct * swap_token_mm = &init_mm;

#define SWAP_TOKEN_CHECK_INTERVAL (HZ * 2)
#define SWAP_TOKEN_TIMEOUT	0
/*
 * Currently disabled; Needs further code to work at HZ * 300.
 */
unsigned long swap_token_default_timeout = SWAP_TOKEN_TIMEOUT;

/*
 * Take the token away if the process had no page faults
 * in the last interval, or if it has held the token for
 * too long.
 */
#define SWAP_TOKEN_ENOUGH_RSS 1
#define SWAP_TOKEN_TIMED_OUT 2
static int should_release_swap_token(struct mm_struct *mm)
{
	int ret = 0;
	if (!mm->recent_pagein)
		ret = SWAP_TOKEN_ENOUGH_RSS;
	else if (time_after(jiffies, swap_token_timeout))
		ret = SWAP_TOKEN_TIMED_OUT;
	mm->recent_pagein = 0;
	return ret;
}

/*
 * Try to grab the swapout protection token.  We only try to
 * grab it once every TOKEN_CHECK_INTERVAL, both to prevent
 * SMP lock contention and to check that the process that held
 * the token before is no longer thrashing.
 */

/*
 * 决定是否将交换标记赋给当前进程
 * 调用该函数的情形:
 * 	1.filemap_nopage()发现请求页不再页高速缓存中
 * 	2.do_swap_page()从交换区读入一个新页
 * 赋予交换标记的条件:
 * 	1.上次调用grab_swap_token()后，至少已过了2s()
 * 	2.在上一次调用grab_swap_token()后，当前拥有交换标记的进程没再提出主缺页，或该进程拥有交换标记的时间超出swap_token_default_timeout个节拍
 *	3.当前进程最近没有获得过交换标记
 * */
void grab_swap_token(void)
{
	struct mm_struct *mm;
	int reason;

	/* We have the token. Let others know we still need it. */
	if (has_swap_token(current->mm)) {
		current->mm->recent_pagein = 1;
		return;
	}

	if (time_after(jiffies, swap_token_check)) {

		/* Can't get swapout protection if we exceed our RSS limit. */
		// if (current->mm->rss > current->mm->rlimit_rss)
		//	return;

		/* ... or if we recently held the token. */
		if (time_before(jiffies, current->mm->swap_token_time))
			return;

		if (!spin_trylock(&swap_token_lock))
			return;

		swap_token_check = jiffies + SWAP_TOKEN_CHECK_INTERVAL;

		mm = swap_token_mm;
		if ((reason = should_release_swap_token(mm))) {
			unsigned long eligible = jiffies;
			if (reason == SWAP_TOKEN_TIMED_OUT) {
				eligible += swap_token_default_timeout;
			}
			mm->swap_token_time = eligible;
			swap_token_timeout = jiffies + swap_token_default_timeout;
			swap_token_mm = current->mm;
		}
		spin_unlock(&swap_token_lock);
	}
	return;
}

/* Called on process exit. */
void __put_swap_token(struct mm_struct *mm)
{
	spin_lock(&swap_token_lock);
	if (likely(mm == swap_token_mm)) {
		swap_token_mm = &init_mm;
		swap_token_check = jiffies;
	}
	spin_unlock(&swap_token_lock);
}
