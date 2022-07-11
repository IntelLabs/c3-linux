/*
 Copyright 2016 Intel Corporation
 SPDX-License-Identifier: MIT
*/
/*
Contains defines used across the kernel to help C3
*/

#ifndef _CC_KERNEL_HELPER_H_
#define _CC_KERNEL_HELPER_H_

#ifdef CONFIG_X86_C3_KERNEL_SPACE

#include <asm/linux_cc.h>

#include <linux/gfp_types.h>

#include <linux/string.h>
#include <asm/barrier.h>
#include <linux/spinlock.h>


extern uint64_t alloc_not_encptr;
extern uint64_t alloc_encptr;
extern uint64_t non_exclude_alloc_not_encptr;
extern uint64_t high_count;
extern spinlock_t icv_lock_spnlock;


__attribute__((unused))
static void cc3_print_alloc_stats(void)
{
	#ifdef printk //printk not always defined where we need to collect stats

	//intentionally left int since fpu not always online where we need it to be
	uint64_t alloc_percent = 100*alloc_encptr/(alloc_encptr+alloc_not_encptr);
	printk("CC3- alloc stats enc: %llu unenc: %llu total: %llu enc_pct: %llu\n", alloc_encptr, alloc_not_encptr, (alloc_encptr+alloc_not_encptr), alloc_percent);
	#endif
}

__attribute__((unused)) noinline
static void* cc3_kernel_encptr(void* ptr, size_t size, gfp_t gfpflags)
{
	ptr_metadata_t ptr_metadata = {0};
	bool is_ca=false;
	bool did_encptr=false;
	bool non_exclude_flag = false;

	unsigned long ccflags;

	if( (___GFP_CC3_INCLUDE&gfpflags) || !( (___GFP_HIGH&gfpflags) || (___GFP_CC3_EXCLUDE&gfpflags) || (__GFP_DMA&gfpflags) || (__GFP_DMA32&gfpflags) ) ) 
	//if( (___GFP_CC3_INCLUDE&gfpflags) || !( (___GFP_CC3_EXCLUDE&gfpflags) || (__GFP_DMA&gfpflags) || (__GFP_DMA32&gfpflags) ) ) 
	{
		is_ca = is_encoded_cc_ptr((uint64_t)ptr);
		if (ptr != NULL && !is_ca ) {	
			if(try_box((uint64_t)ptr, size, &ptr_metadata)) {
				ptr = (void *)cc_isa_encptr((uint64_t)ptr, &ptr_metadata);
				did_encptr=true;
			}

			spin_lock_irqsave(&icv_lock_spnlock, ccflags);

			cc_set_icv_lock(0);
			memset(ptr, 0 ,size);
			cc_set_icv_lock(1);

			spin_unlock_irqrestore(&icv_lock_spnlock, ccflags);
		}
		gfpflags = (gfpflags & ~___GFP_CC3_INCLUDE); //turn off our flag

	}
	non_exclude_flag = (___GFP_HIGH&gfpflags) || (__GFP_DMA&gfpflags) || (__GFP_DMA32&gfpflags);
	//non_exclude_flag = (__GFP_DMA&gfpflags) || (__GFP_DMA32&gfpflags);
	if( (___GFP_HIGH&gfpflags) )
		high_count++;

	if(!(___GFP_CC3_NO_COUNT&gfpflags)){

		if(did_encptr){
			alloc_encptr++;
		} else {
			alloc_not_encptr++;
			if(non_exclude_flag)
				non_exclude_alloc_not_encptr++;
		}
	}

	return ptr;
}
__attribute__((unused, optimize("O0"))) noinline
static void clear_icv(void *ptr, size_t size)
{
	unsigned long ccflags;
	spin_lock_irqsave(&icv_lock_spnlock, ccflags);
	cc_set_icv_lock(0);

	for (void *end = (ptr + size); ptr < end; ptr += sizeof(char)) {

		__asm__ volatile("mov (%[ptr]), %%al  \n"
						 "mov %%al, (%[ptr])  \n"
						 : [ptr] "+r"(ptr)
						 :
						 : "memory", "rax");
	}
	cc_set_icv_lock(1);

	spin_unlock_irqrestore(&icv_lock_spnlock, ccflags);
}

#endif // CONFIG_X86_C3_KERNEL_SPACE

#endif  // _CC_KERNEL_HELPER_H_
