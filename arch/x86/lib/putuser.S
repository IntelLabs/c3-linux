/* SPDX-License-Identifier: GPL-2.0 */
/*
 * __put_user functions.
 *
 * (C) Copyright 2005 Linus Torvalds
 * (C) Copyright 2005 Andi Kleen
 * (C) Copyright 2008 Glauber Costa
 *
 * These functions have a non-standard call interface
 * to make them more efficient, especially as they
 * return an error value in addition to the "real"
 * return value.
 */
#include <linux/linkage.h>
#include <asm/thread_info.h>
#include <asm/errno.h>
#include <asm/asm.h>
#include <asm/smap.h>
#include <asm/export.h>
#include <asm/cc.h>

#ifndef CONFIG_X86_CC /* FIXME: Make this a proper kernel config */
#define CONFIG_X86_CC
#endif /* CONFIG_X86_CC */

/* FIXME: Fix put_user check properly (conf to enable CC after init?) */
#undef CONFIG_X86_CC
#define CC_DISABLE_PUT_USER_CHECK

/*
 * __put_user_X
 *
 * Inputs:	%eax[:%edx] contains the data
 *		%ecx contains the address
 *
 * Outputs:	%ecx is error code (0 or -EFAULT)
 *
 * Clobbers:	%ebx needed for task pointer
 *          	%edx to store decrypted ptr
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */

#ifdef CONFIG_X86_5LEVEL
#define LOAD_TASK_SIZE_MINUS_N(n) \
	ALTERNATIVE __stringify(mov $((1 << 47) - 4096 - (n)),%rbx), \
		    __stringify(mov $((1 << 56) - 4096 - (n)),%rbx), X86_FEATURE_LA57
#else
#define LOAD_TASK_SIZE_MINUS_N(n) \
	mov $(TASK_SIZE_MAX - (n)),%_ASM_BX
#endif

.text
SYM_FUNC_START(__put_user_1)
#ifdef CONFIG_X86_CC
	mov %_ASM_CX, %_ASM_DX
	CC_DECRYPT_CA_RDX
	LOAD_TASK_SIZE_MINUS_N(0)
	cmp %_ASM_BX,%_ASM_DX
#else /* CONFIG_X86_CC */
	LOAD_TASK_SIZE_MINUS_N(0)
	cmp %_ASM_BX,%_ASM_CX
#endif /* !CONFIG_X86_CC */
#ifndef CC_DISABLE_PUT_USER_CHECK
	jae .Lbad_put_user
#endif /* CC_DISABLE_PUT_USER_CHECK */
SYM_INNER_LABEL(__put_user_nocheck_1, SYM_L_GLOBAL)
	ASM_STAC
1:	movb %al,(%_ASM_CX)
	xor %ecx,%ecx
	ASM_CLAC
	ret
SYM_FUNC_END(__put_user_1)
EXPORT_SYMBOL(__put_user_1)
EXPORT_SYMBOL(__put_user_nocheck_1)

SYM_FUNC_START(__put_user_2)
#ifdef CONFIG_X86_CC
	mov %_ASM_CX, %_ASM_DX
	CC_DECRYPT_CA_RDX
	LOAD_TASK_SIZE_MINUS_N(1)
	cmp %_ASM_BX,%_ASM_DX
#else /* CONFIG_X86_CC */
	LOAD_TASK_SIZE_MINUS_N(1)
	cmp %_ASM_BX,%_ASM_CX
#endif /* !CONFIG_X86_CC */
#ifndef CC_DISABLE_PUT_USER_CHECK
	jae .Lbad_put_user
#endif /* CC_DISABLE_PUT_USER_CHECK */
SYM_INNER_LABEL(__put_user_nocheck_2, SYM_L_GLOBAL)
	ASM_STAC
2:	movw %ax,(%_ASM_CX)
	xor %ecx,%ecx
	ASM_CLAC
	ret
SYM_FUNC_END(__put_user_2)
EXPORT_SYMBOL(__put_user_2)
EXPORT_SYMBOL(__put_user_nocheck_2)

SYM_FUNC_START(__put_user_4)
#ifdef CONFIG_X86_CC
	mov %_ASM_CX, %_ASM_DX
	CC_DECRYPT_CA_RDX
	LOAD_TASK_SIZE_MINUS_N(3)
	cmp %_ASM_BX,%_ASM_DX
#else /* CONFIG_X86_CC */
	LOAD_TASK_SIZE_MINUS_N(3)
	cmp %_ASM_BX,%_ASM_CX
#endif /* !CONFIG_X86_CC */
#ifndef CC_DISABLE_PUT_USER_CHECK
	jae .Lbad_put_user
#endif /* CC_DISABLE_PUT_USER_CHECK */
SYM_INNER_LABEL(__put_user_nocheck_4, SYM_L_GLOBAL)
	ASM_STAC
3:	movl %eax,(%_ASM_CX)
	xor %ecx,%ecx
	ASM_CLAC
	ret
SYM_FUNC_END(__put_user_4)
EXPORT_SYMBOL(__put_user_4)
EXPORT_SYMBOL(__put_user_nocheck_4)

SYM_FUNC_START(__put_user_8)
#ifdef CONFIG_X86_CC
	mov %_ASM_CX, %_ASM_DX
	CC_DECRYPT_CA_RDX
	LOAD_TASK_SIZE_MINUS_N(7)
	cmp %_ASM_BX,%_ASM_DX
#else /* CONFIG_X86_CC */
	LOAD_TASK_SIZE_MINUS_N(7)
	cmp %_ASM_BX,%_ASM_CX
#endif /* !CONFIG_X86_CC */
#ifndef CC_DISABLE_PUT_USER_CHECK
	jae .Lbad_put_user
#endif /* CC_DISABLE_PUT_USER_CHECK */
SYM_INNER_LABEL(__put_user_nocheck_8, SYM_L_GLOBAL)
	ASM_STAC
4:	mov %_ASM_AX,(%_ASM_CX)
#ifdef CONFIG_X86_32
5:	movl %edx,4(%_ASM_CX)
#endif
	xor %ecx,%ecx
	ASM_CLAC
	RET
SYM_FUNC_END(__put_user_8)
EXPORT_SYMBOL(__put_user_8)
EXPORT_SYMBOL(__put_user_nocheck_8)

SYM_CODE_START_LOCAL(.Lbad_put_user_clac)
	ASM_CLAC
.Lbad_put_user:
	movl $-EFAULT,%ecx
	RET
SYM_CODE_END(.Lbad_put_user_clac)

	_ASM_EXTABLE_UA(1b, .Lbad_put_user_clac)
	_ASM_EXTABLE_UA(2b, .Lbad_put_user_clac)
	_ASM_EXTABLE_UA(3b, .Lbad_put_user_clac)
	_ASM_EXTABLE_UA(4b, .Lbad_put_user_clac)
#ifdef CONFIG_X86_32
	_ASM_EXTABLE_UA(5b, .Lbad_put_user_clac)
#endif
