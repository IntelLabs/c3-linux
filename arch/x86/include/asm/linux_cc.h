/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/* Copyright (C) 2022 Intel Corporation */
#ifndef _ASM_X86_CC_H
#define _ASM_X86_CC_H


#ifdef CONFIG_X86_C3_USER_SPACE

#define CC_SHADOW_RIP_ENABLE
#define CC_COREDUMP_SUPPORT

// #define CC_USE_FIXED_ADDR_KEY
// #define CC_USE_FIXED_DATA_KEYS

#ifdef __ASSEMBLY__

.macro CC_DECRYPT_CA_RCX
	movabs $0x3fffffffffff,%rbx
	and    %rcx, %rbx
	cmp    %rcx, %rbx
	je     .+0x6
	.byte  0xf0, 0x48, 0x01, 0xc9
.endm

.macro CC_DECRYPT_CA_RDX
	movabs $0x3fffffffffff,%rbx
	and    %rdx, %rbx
	cmp    %rdx, %rbx
	je     .+0x6
	.byte  0xf0, 0x48, 0x01, 0xd2
.endm

#else /* !__ASSEMBLY__ */

#include "linux_cc_cc_globals.h"
#include "linux_cc_try_box.h"

struct linux_binprm;

typedef struct cc_linux_thread_conf {
	struct cc_context ctx_raw;
	uint64_t initial_stack_rlimit_cur;
} cc_linux_thread_conf_t;

#define task_cc_conf(task) (&((task)->thread.cc_context))
#define task_cc_context_raw(task) (&((task)->thread.cc_context.ctx_raw))

static __always_inline bool
cc_conf_is_enabled(const cc_linux_thread_conf_t *cc_conf)
{
	const cc_context_t *ctx = &cc_conf->ctx_raw;
	return cc_ctx_get_cc_enabled(ctx);
}
#define task_cc_is_enabled(t) (cc_conf_is_enabled(task_cc_conf(t)))

#define task_cc_save_context(t) (cc_save_context(task_cc_context_raw(t)))
#define task_cc_load_context(t) (cc_load_context(task_cc_context_raw(t)))

extern void cc_conf_dump(const cc_linux_thread_conf_t *ctx, const char *msg);

extern void cc_conf_init(cc_linux_thread_conf_t *ctx,
			 const struct linux_binprm *brpm);
extern void cc_conf_clone(const cc_linux_thread_conf_t *parent,
			  cc_linux_thread_conf_t *ctx, uint64_t clone_flags);

#endif /* !__ASSEMBLY__ */
#endif /* CONFIG_X86_C3_USER_SPACE */

#ifdef CONFIG_X86_C3_KERNEL_SPACE

#include "linux_cc_cc_globals.h"
#include "linux_cc_try_box.h"

#endif // CONFIG_X86_C3_KERNEL_SPACE

#endif /* _ASM_X86_CC_H */