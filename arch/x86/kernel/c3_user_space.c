// SPDX-License-Identifier: GPL-2.0 OR MIT
/* Copyright (C) 2023 Intel Corporation */
#include <asm/alternative.h>
#include <asm/linux_cc.h>
#include <linux/binfmts.h>
#include <linux/random.h>
#include <linux/printk.h>

#define CC_ADDR_KEY_SIZE C3_KEY_SIZE(CC_POINTER_CIPHER)
#define CC_DATA_KEY_SIZE C3_KEY_SIZE(CC_DATA_CIPHER)

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



static __always_inline void cc_conf_init_data_keys(cc_linux_thread_conf_t *ctx)
{
#ifdef CC_USE_FIXED_DATA_KEYS
	static const data_key_bytes_t fixed_data_key = DEF_DATA_KEY_BYTES;
	printk(KERN_NOTICE "Setting fixed C3 data keys\n");
	memcpy(&ctx->ctx_raw.dp_key_bytes_, fixed_data_key, CC_DATA_KEY_SIZE);
	memcpy(&ctx->ctx_raw.ds_key_bytes_, fixed_data_key, CC_DATA_KEY_SIZE);
	memcpy(&ctx->ctx_raw.c_key_bytes_, fixed_data_key, CC_DATA_KEY_SIZE);
#else
	printk(KERN_NOTICE "Setting random C3 data keys\n");
	get_random_bytes(&ctx->ctx_raw.dp_key_bytes_, CC_DATA_KEY_SIZE);
	get_random_bytes(&ctx->ctx_raw.ds_key_bytes_, CC_DATA_KEY_SIZE);
	get_random_bytes(&ctx->ctx_raw.c_key_bytes_, CC_DATA_KEY_SIZE);
#endif
}

static __always_inline void
cc_conf_init_pointer_keys(cc_linux_thread_conf_t *ctx)
{
#ifdef CC_USE_FIXED_ADDR_KEY
	static const pointer_key_bytes_t fixed_addr_key = DEF_ADDR_KEY_BYTES;
	printk(KERN_NOTICE "Setting fixed C3 address keys\n");
	memcpy(&ctx->ctx_raw.addr_key_bytes_, fixed_addr_key, CC_ADDR_KEY_SIZE);
#else
	printk(KERN_NOTICE "Setting random C3 address keys\n");
	get_random_bytes(&ctx->ctx_raw.addr_key_bytes_, CC_ADDR_KEY_SIZE);
#endif
}

void cc_conf_init(cc_linux_thread_conf_t *ctx, const struct linux_binprm *bprm)
{
	int is_enabled = 0;

	// Zero out all configuration first
	memset(ctx, 0, sizeof(cc_linux_thread_conf_t));

	if (bprm->cc_enabled) {
		printk(KERN_NOTICE "Enabling C3 for process\n");
		cc_ctx_set_cc_enabled(&ctx->ctx_raw, 1);
		is_enabled = 1;
	}

#ifdef CC_INTEGRITY_ENABLE
	if (bprm->cc_icv_enabled) {
		printk(KERN_NOTICE "Enabling C3 integrity for process\n");
		cc_ctx_set_icv_enabled(&ctx->ctx_raw, 1);
	}
#endif



	if (is_enabled) {
		// Initalize the keys
		cc_conf_init_data_keys(ctx);
		cc_conf_init_pointer_keys(ctx);
		// Then load configuration
		cc_load_context(&(ctx->ctx_raw));
	}
}

void cc_conf_clone(const cc_linux_thread_conf_t *parent,
		   cc_linux_thread_conf_t *ctx, uint64_t clone_flags)
{
	memcpy(ctx, parent, sizeof(cc_linux_thread_conf_t));

}

extern void cc_conf_dump(const cc_linux_thread_conf_t *ctx, const char *msg)
{
	printk(KERN_NOTICE "%s (cc%d)\n", msg, cc_ctx_get_cc_enabled(&ctx->ctx_raw));


}