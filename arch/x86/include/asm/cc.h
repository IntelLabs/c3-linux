#ifndef _ASM_X86_CC_H
#define _ASM_X86_CC_H

#ifndef CONFIG_X86_CC /* FIXME: Make this a proper kernel config */
#define CONFIG_X86_CC 1
#endif /* CONFIG_X86_CC */




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
#include <asm/alternative.h>
#include <linux/printk.h>

#define CC_ADDR_KEY_SIZE 16
#define CC_DATA_KEY_SIZE 32

typedef uint8_t cc_addr_key_bytes_t[CC_ADDR_KEY_SIZE];
typedef uint8_t cc_data_key_bytes_t[CC_DATA_KEY_SIZE];

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


	struct __attribute__((__packed__)) {
		union {
			struct {
				uint64_t unused : 61;
				uint64_t rsvd2 : 1;
				uint64_t rsvd1 : 1;
				uint64_t cc_enabled : 1;
			};
			uint64_t raw;
		} flags;  // 64-bit flags field
		uint64_t reserved1;
		cc_data_key_bytes_t s_key_bytes;  // shared data key
		cc_data_key_bytes_t p_key_bytes;  // private data key
		cc_data_key_bytes_t c_key_bytes;  // code key
		cc_addr_key_bytes_t a_key_bytes;  // address / pointer key
	} ctx_raw;
} cc_context_t;

#ifdef LEGACY_32B_FORMAT
	#define TOP_CANONICAL_BIT_OFFSET 55
	#define PLAINTEXT_SIZE 26
	#define CIPHERTEXT_SIZE 32
	#define SIZE_SIZE 5
	#define ADJUST_SIZE 1
#else // new 24b cipher format
	#define TOP_CANONICAL_BIT_OFFSET 47
	#define PLAINTEXT_SIZE 32
	#define CIPHERTEXT_SIZE 24
	#define SIZE_SIZE 6
	#define CIPHERTEXT_LOW_SIZE 15
	#define S_BIT_SIZE 1
	#define PLAINTEXT_VERSION_SIZE 4
	#define CIPHERTEXT_HIGH_OFFSET  (PLAINTEXT_SIZE+CIPHERTEXT_LOW_SIZE+S_BIT_SIZE)
	#define CANARY_SIZE (CIPHERTEXT_SIZE-PLAINTEXT_VERSION_SIZE-CIPHERTEXT_LOW_SIZE)
	#define S_EXTENDED_SIZE (64-2*S_BIT_SIZE-CANARY_SIZE-CIPHERTEXT_LOW_SIZE-PLAINTEXT_SIZE)
	#define SPECIAL_SIZE_ENCODING_WITH_ADJUST 31 
#endif

#define PLAINTEXT_OFFSET 0
#define CIPHERTEXT_OFFSET (PLAINTEXT_OFFSET + PLAINTEXT_SIZE)
#define VERSION_OFFSET (CIPHERTEXT_OFFSET + CIPHERTEXT_SIZE - VERSION_SIZE)
#define SIZE_OFFSET (CIPHERTEXT_OFFSET + CIPHERTEXT_SIZE)
#ifdef LEGACY_32B_FORMAT
	#define ADJUST_OFFSET (SIZE_OFFSET + SIZE_SIZE)
#endif

#define FMASK 0xFFFFFFFFFFFFFFFFULL
#define SIMON_ROUNDS 10

#define BOX_PAD_FOR_STRLEN_FIX 48

// Use a prime number for depth for optimum results
#define QUARANTINE_DEPTH 373
#define QUARANTINE_WIDTH 2

static __always_inline uint64_t get_low_canonical_bits(uint64_t pointer) {
	return pointer & (FMASK >> (64-TOP_CANONICAL_BIT_OFFSET-1));
}

static __always_inline int is_canonical(uint64_t pointer) {
	return (pointer == get_low_canonical_bits(pointer)) ? 1 : 0;
}

static __always_inline int is_encoded_pointer(const void* p) {
  return !is_canonical((uint64_t) p);
}

static __always_inline int cc_is_encoded_pointer(const u64 ptr) {
        return is_encoded_pointer((const void *) ptr);
}

static __always_inline u64 cc_decrypt_pointer(u64 ptr) {
	asm(".byte 0xf0\n"
	    ".byte 0x48\n"
	    ".byte 0x01\n"
	    ".byte 0xc0\n"
	    : "+a"(ptr) : : );
	return ptr;
}

static __always_inline void cc_save_context(const cc_context_t *const ctx) {
	const u64 ptr = (u64)&(ctx->ctx_raw);
	__asm__ __volatile__(".byte 0xf0; .byte 0x2f" : : "a" (ptr));
}

static __always_inline void cc_load_context(cc_context_t *const ctx) {
	const u64 ptr = (u64)&ctx->ctx_raw;
	__asm__ __volatile__(".byte 0xf0; .byte 0xfa" : : "a" (ptr));
}

static __always_inline bool
cc_context_cc_enabled(const cc_context_t *const ctx) {
	return ctx->ctx_raw.flags.cc_enabled;
}

static __always_inline void
cc_context_set_cc_enabled(cc_context_t *const ctx, bool val) {
	ctx->ctx_raw.flags.cc_enabled = val;
}




static __always_inline bool
cc_context_is_enabled(const cc_context_t *const ctx) {
	if (cc_context_cc_enabled(ctx))
		return true;


	return false;
}




static __always_inline void
cc_context_dump_ctx(const cc_context_t *ctx, const char *msg) {
	printk(KERN_NOTICE "%s (cc%d)\n", msg, cc_context_cc_enabled(ctx));






}

extern void cc_init_context(cc_context_t *ctx);
extern void cc_clone_context(const cc_context_t *parent,
                             cc_context_t *ctx, 
                             uint64_t clone_flags);

#endif /* !__ASSEMBLY__ */
#endif /* _ASM_X86_CC_H */