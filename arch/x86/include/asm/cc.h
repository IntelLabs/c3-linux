#ifndef _ASM_X86_CC_H
#define _ASM_X86_CC_H

#ifndef CONFIG_X86_CC /* FIXME: Make this a proper kernel config */
#define CONFIG_X86_CC 1
#endif /* CONFIG_X86_CC */




#define CC_COREDUMP_SUPPORT

// #define CC_USE_FIXED_ADDR_KEY
// #define CC_USE_FIXED_DATA_KEYS

#include <asm/page_64_types.h>

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

#endif /* __ASSEMBLY__ */

#ifndef __ASSEMBLY__
#define _CC_GLOBALS_NO_INCLUDES_
#include "../../../../../../../malloc/cc_globals.h"
#include <asm/alternative.h>
#include <linux/printk.h>

#define CC_ADDR_KEY_SIZE KEY_SIZE(CC_POINTER_CIPHER)
#define CC_DATA_KEY_SIZE KEY_SIZE(CC_DATA_CIPHER)


#define DEF_DATA_KEY_BYTES                                                     \
    {                                                                          \
        0xb5, 0x82, 0x4d, 0x03, 0x17, 0x5c, 0x25, 0x2a,                        \
        0xfc, 0x71, 0x1e, 0x01, 0x02, 0x60, 0x87, 0x91                         \
    }

#define DEF_ADDR_KEY_BYTES                                                     \
    {                                                                          \
        0xd1, 0xbe, 0x2c, 0xdb, 0xb5, 0x82, 0x4d, 0x03,                        \
        0x17, 0x5c, 0x25, 0x2a, 0x20, 0xb6, 0xf2, 0x93,                        \
        0xfd, 0x01, 0x96, 0xe7, 0xb5, 0xe6, 0x88, 0x1c,                        \
        0xb3, 0x69, 0x22, 0x60, 0x38, 0x09, 0xf6, 0x68                         \
    }

typedef struct {


	struct cc_context ctx_raw;
} cc_context_t;

static __always_inline bool
cc_context_is_enabled(const cc_context_t *const ctx) {
	if (cc_ctx_get_cc_enabled(&ctx->ctx_raw))
		return true;


	return false;
}




static __always_inline void
cc_context_dump_ctx(const cc_context_t *ctx, const char *msg) {
	printk(KERN_NOTICE "%s (cc%d)\n", msg, cc_ctx_get_cc_enabled(&ctx->ctx_raw));






}

extern void cc_init_context(cc_context_t *ctx);
extern void cc_clone_context(const cc_context_t *parent,
                             cc_context_t *ctx, 
                             uint64_t clone_flags);

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_CC_H */