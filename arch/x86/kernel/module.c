// SPDX-License-Identifier: GPL-2.0-or-later
/*  Kernel module help for x86.
    Copyright (C) 2001 Rusty Russell.

*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/moduleloader.h>
#include <linux/elf.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/kasan.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/jump_label.h>
#include <linux/random.h>
#include <linux/memory.h>

#include <asm/text-patching.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <asm/unwind.h>

#ifdef CONFIG_X86_C3_KERNEL_SPACE

#ifndef _CC_GLOBALS_NO_INCLUDES_
#define _CC_GLOBALS_NO_INCLUDES_
#endif
#include <linux/ctype.h>
// #include <linux/try_box.h>
#include <asm/linux_cc.h> // #include <linux/cc_globals.h>

#endif // CONFIG_X86_C3_KERNEL_SPACE

#if 0
#define DEBUGP(fmt, ...)				\
	printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#else
#define DEBUGP(fmt, ...)				\
do {							\
	if (0)						\
		printk(KERN_DEBUG fmt, ##__VA_ARGS__);	\
} while (0)
#endif

#ifdef CONFIG_RANDOMIZE_BASE
static unsigned long module_load_offset;

/* Mutex protects the module_load_offset. */
static DEFINE_MUTEX(module_kaslr_mutex);

static unsigned long int get_module_load_offset(void)
{
	if (kaslr_enabled()) {
		mutex_lock(&module_kaslr_mutex);
		/*
		 * Calculate the module_load_offset the first time this
		 * code is called. Once calculated it stays the same until
		 * reboot.
		 */
		if (module_load_offset == 0)
			module_load_offset =
				get_random_u32_inclusive(1, 1024) * PAGE_SIZE;
		mutex_unlock(&module_kaslr_mutex);
	}
	return module_load_offset;
}
#else
static unsigned long int get_module_load_offset(void)
{
	return 0;
}
#endif

void *module_alloc(unsigned long size)
{
	gfp_t gfp_mask = GFP_KERNEL;
	void *p;

	if (PAGE_ALIGN(size) > MODULES_LEN)
		return NULL;

	p = __vmalloc_node_range(size, MODULE_ALIGN,
				 MODULES_VADDR + get_module_load_offset(),
				 MODULES_END, gfp_mask, PAGE_KERNEL,
				 VM_FLUSH_RESET_PERMS | VM_DEFER_KMEMLEAK,
				 NUMA_NO_NODE, __builtin_return_address(0));

	if (p && (kasan_alloc_module_shadow(p, size, gfp_mask) < 0)) {
		vfree(p);
		return NULL;
	}

	return p;
}

#ifdef CONFIG_X86_32
int apply_relocate(Elf32_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *me)
{
	unsigned int i;
	Elf32_Rel *rel = (void *)sechdrs[relsec].sh_addr;
	Elf32_Sym *sym;
	uint32_t *location;

	DEBUGP("Applying relocate section %u to %u\n",
	       relsec, sechdrs[relsec].sh_info);
	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change */
		location = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr
			+ rel[i].r_offset;
		/* This is the symbol it is referring to.  Note that all
		   undefined symbols have been resolved.  */
		sym = (Elf32_Sym *)sechdrs[symindex].sh_addr
			+ ELF32_R_SYM(rel[i].r_info);

		switch (ELF32_R_TYPE(rel[i].r_info)) {
		case R_386_32:
			/* We add the value into the location given */
			*location += sym->st_value;
			break;
		case R_386_PC32:
		case R_386_PLT32:
			/* Add the value, subtract its position */
			*location += sym->st_value - (uint32_t)location;
			break;
		default:
			pr_err("%s: Unknown relocation: %u\n",
			       me->name, ELF32_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}
	}
	return 0;
}
#else /*X86_64*/
#ifdef CONFIG_X86_PIE
static u64 find_got_kernel_entry(Elf64_Sym *sym, const Elf64_Rela *rela)
{
	u64 *pos;

	for (pos = (u64 *)__start_got; pos < (u64 *)__end_got; pos++)
		if (*pos == sym->st_value)
			return (u64)pos + rela->r_addend;
	return 0;
}
#endif

static int __write_relocate_add(Elf64_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *me,
		   void *(*write)(void *dest, const void *src, size_t len),
		   bool apply)
{
	unsigned int i;
	Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;
	Elf64_Sym *sym;
	void *loc;
	u64 val;
	u64 zero = 0ULL;
#ifdef CONFIG_X86_C3_KERNEL_SPACE
	void *new_loc;
	void *unencoded_loc;
	u64 new_val;
	u64 unencoded_val;
	bool encode_location = false;
	bool encode_value = true;

	char* sec_name = me->secstrings + sechdrs[relsec].sh_name;
	encode_value = (me->encoded_address_adjust == 0) ? false : true;
	if (me->encoded_address_adjust !=0 ){
		if (sec_name[6] == 'd' && sec_name[7] == 'a') {
			encode_location = true ;// ".data"
		} else if (sec_name[6] == 'r' && sec_name[7] == 'o') {
			encode_location = true ;// ".rodata*"
		} else if (sec_name[6] == 'b' && sec_name[7] == 's') {
			encode_location = true ;// ".bss"

		/*
		} else if (sec_name[11] == 'd' && sec_name[12] == 'a') {
			encode_location = true ;// ".exit.data" and "init.data"
		*/

		/*
		} else if (sec_name[11] == 'r' && sec_name[12] == 'o') {
			encode_location = true ;// ".exit.rodata" and "init.rodata"
		} else if (sec_name[6] == 's' && sec_name[7] == 'm' && sec_name[8] == 'p') {
			encode_location = true ;// ".smp_locks"
			//encode_value = false;
		} else if (sec_name[7] == 'p' && sec_name[8] == 'a' && sec_name[9] == 'r') {
			encode_location = true ;// "__param"
			//encode_value = false;
		*/
		} else if (sec_name[7] == 'p' && sec_name[8] == 'a' && sec_name[9] == 'r') {
			encode_value = false ;// "__param"
		} else if (sec_name[7] == 't' && sec_name[8] == 'r' && sec_name[9] == 'a') {
			encode_value = false ;// "__tracepoints"
		} else if (sec_name[7] == 'm' && sec_name[8] == 'c') {
			encode_value = false; // "__mcount_loc". Disabling ponter encoding for ftrace
		}

		// Make sure this_module always uses the CA (also outside the module)
		// otherwise the data will be scrambled
		if (strcmp(".gnu.linkonce.this_module", sec_name + 5) == 0) {
				encode_location = true ;// .gnu.linkonce.this_module
		}

		/*
		if (strcmp("__ex_table", sec_name + 5) == 0) {
				encode_location = true ;// __ex_table
		}
		*/
	}
#endif // CONFIG_X86_C3_KERNEL_SPACE
	DEBUGP("%s relocate section %u to %u\n",
	       apply ? "Applying" : "Clearing",
	       relsec, sechdrs[relsec].sh_info);
	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		size_t size;

		/* This is where to make the change */
		loc = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr
			+ rel[i].r_offset;

		/* This is the symbol it is referring to.  Note that all
		   undefined symbols have been resolved.  */
		sym = (Elf64_Sym *)sechdrs[symindex].sh_addr
			+ ELF64_R_SYM(rel[i].r_info);

		DEBUGP("type %d st_value %Lx r_addend %Lx loc %Lx\n",
		       (int)ELF64_R_TYPE(rel[i].r_info),
		       sym->st_value, rel[i].r_addend, (u64)loc);

		val = sym->st_value + rel[i].r_addend;
#ifdef CONFIG_X86_C3_KERNEL_SPACE
		new_val = val;
		if (ELF64_R_TYPE(rel[i].r_info) == R_X86_64_PLT32) {
			encode_value = false;
		}
		if (encode_value) {
			new_val += me->encoded_address_adjust;
		}
		new_loc = loc;
		if (encode_location)
			new_loc = (void*) ((u64)loc + me->encoded_address_adjust);
		unencoded_loc = loc;
		unencoded_val = val;
		loc = new_loc;
		val = new_val;
#endif // CONFIG_X86_C3_KERNEL_SPACE
		switch (ELF64_R_TYPE(rel[i].r_info)) {
		case R_X86_64_NONE:
			continue;  /* nothing to write */
		case R_X86_64_64:
			size = 8;
			break;
#ifndef CONFIG_X86_PIE
#ifdef CONFIG_X86_C3_KERNEL_SPACE
		BUILD_ASSERT(0); //ERROR: compiling without CONFIG_X86_PIE
#endif // CONFIG_X86_C3_KERNEL_SPACE
		case R_X86_64_32:
			if (val != *(u32 *)&val)
				goto overflow;
			size = 4;
			break;
		case R_X86_64_32S:
			if ((s64)val != *(s32 *)&val)
				goto overflow;
			size = 4;
			break;
#else
		case R_X86_64_GOTPCREL:
			val = find_got_kernel_entry(sym, rel);
			if (!val)
				goto unexpected_got_reference;
			fallthrough;
#endif
		case R_X86_64_PC32:
		case R_X86_64_PLT32:
#ifdef CONFIG_X86_C3_KERNEL_SPACE
			val = unencoded_val - (u64) unencoded_loc;
#else // !CONFIG_X86_C3_KERNEL_SPACE
			val -= (u64)loc;
#endif // CONFIG_X86_C3_KERNEL_SPACE
			size = 4;
			break;
		case R_X86_64_PC64:
#ifdef CONFIG_X86_C3_KERNEL_SPACE
			val = unencoded_val - (u64) unencoded_loc;
#else // !CONFIG_X86_C3_KERNEL_SPACE
			val -= (u64)loc;
#endif // CONFIG_X86_C3_KERNEL_SPACE
			size = 8;
			break;
		default:
			pr_err("%s: Unknown rela relocation: %llu\n",
			       me->name, ELF64_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}

		if (apply) {
			if (memcmp(loc, &zero, size)) {
				pr_err("x86/modules: Invalid relocation target, existing value is nonzero for type %d, loc %p, val %Lx\n",
				       (int)ELF64_R_TYPE(rel[i].r_info), loc, val);
				return -ENOEXEC;
			}
			write(loc, &val, size);
		} else {
			if (memcmp(loc, &val, size)) {
				pr_warn("x86/modules: Invalid relocation target, existing value does not match expected value for type %d, loc %p, val %Lx\n",
					(int)ELF64_R_TYPE(rel[i].r_info), loc, val);
				return -ENOEXEC;
			}
			write(loc, &zero, size);
		}
	}
	return 0;

#ifdef CONFIG_X86_PIE
unexpected_got_reference:
	pr_err("Target got entry doesn't exist in kernel got, loc %p\n", loc);
	return -ENOEXEC;
#else
overflow:
	pr_err("overflow in relocation type %d val %Lx\n",
	       (int)ELF64_R_TYPE(rel[i].r_info), val);
	pr_err("`%s' likely not compiled with -mcmodel=kernel\n",
	       me->name);
#endif

	return -ENOEXEC;
}

static int write_relocate_add(Elf64_Shdr *sechdrs,
			      const char *strtab,
			      unsigned int symindex,
			      unsigned int relsec,
			      struct module *me,
			      bool apply)
{
	int ret;
	bool early = me->state == MODULE_STATE_UNFORMED;
	void *(*write)(void *, const void *, size_t) = memcpy;

	if (!early) {
		write = text_poke;
		mutex_lock(&text_mutex);
	}

	ret = __write_relocate_add(sechdrs, strtab, symindex, relsec, me,
				   write, apply);

	if (!early) {
		text_poke_sync();
		mutex_unlock(&text_mutex);
	}

	return ret;
}

int apply_relocate_add(Elf64_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *me)
{
	return write_relocate_add(sechdrs, strtab, symindex, relsec, me, true);
}

#ifdef CONFIG_LIVEPATCH
void clear_relocate_add(Elf64_Shdr *sechdrs,
			const char *strtab,
			unsigned int symindex,
			unsigned int relsec,
			struct module *me)
{
	write_relocate_add(sechdrs, strtab, symindex, relsec, me, false);
}
#endif

#endif

int module_finalize(const Elf_Ehdr *hdr,
		    const Elf_Shdr *sechdrs,
		    struct module *me)
{
	const Elf_Shdr *s, *alt = NULL, *locks = NULL,
		*para = NULL, *orc = NULL, *orc_ip = NULL,
		*retpolines = NULL, *returns = NULL, *ibt_endbr = NULL,
		*calls = NULL, *cfi = NULL;
	char *secstrings = (void *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;

	for (s = sechdrs; s < sechdrs + hdr->e_shnum; s++) {
		if (!strcmp(".altinstructions", secstrings + s->sh_name))
			alt = s;
		if (!strcmp(".smp_locks", secstrings + s->sh_name))
			locks = s;
		if (!strcmp(".parainstructions", secstrings + s->sh_name))
			para = s;
		if (!strcmp(".orc_unwind", secstrings + s->sh_name))
			orc = s;
		if (!strcmp(".orc_unwind_ip", secstrings + s->sh_name))
			orc_ip = s;
		if (!strcmp(".retpoline_sites", secstrings + s->sh_name))
			retpolines = s;
		if (!strcmp(".return_sites", secstrings + s->sh_name))
			returns = s;
		if (!strcmp(".call_sites", secstrings + s->sh_name))
			calls = s;
		if (!strcmp(".cfi_sites", secstrings + s->sh_name))
			cfi = s;
		if (!strcmp(".ibt_endbr_seal", secstrings + s->sh_name))
			ibt_endbr = s;
	}

	/*
	 * See alternative_instructions() for the ordering rules between the
	 * various patching types.
	 */
	if (para) {
		void *pseg = (void *)para->sh_addr;
		apply_paravirt(pseg, pseg + para->sh_size);
	}
	if (retpolines || cfi) {
		void *rseg = NULL, *cseg = NULL;
		unsigned int rsize = 0, csize = 0;

		if (retpolines) {
			rseg = (void *)retpolines->sh_addr;
			rsize = retpolines->sh_size;
		}

		if (cfi) {
			cseg = (void *)cfi->sh_addr;
			csize = cfi->sh_size;
		}

		apply_fineibt(rseg, rseg + rsize, cseg, cseg + csize);
	}
	if (retpolines) {
		void *rseg = (void *)retpolines->sh_addr;
		apply_retpolines(rseg, rseg + retpolines->sh_size);
	}
	if (returns) {
		void *rseg = (void *)returns->sh_addr;
		apply_returns(rseg, rseg + returns->sh_size);
	}
	if (alt) {
		/* patch .altinstructions */
		void *aseg = (void *)alt->sh_addr;
		apply_alternatives(aseg, aseg + alt->sh_size);
	}
	if (calls || para) {
		struct callthunk_sites cs = {};

		if (calls) {
			cs.call_start = (void *)calls->sh_addr;
			cs.call_end = (void *)calls->sh_addr + calls->sh_size;
		}

		if (para) {
			cs.pv_start = (void *)para->sh_addr;
			cs.pv_end = (void *)para->sh_addr + para->sh_size;
		}

		callthunks_patch_module_calls(&cs, me);
	}
	if (ibt_endbr) {
		void *iseg = (void *)ibt_endbr->sh_addr;
		apply_ibt_endbr(iseg, iseg + ibt_endbr->sh_size);
	}
	if (locks) {
		void *lseg = (void *)locks->sh_addr;
		void *text = me->core_layout.base;
		void *text_end = text + me->core_layout.text_size;
		alternatives_smp_module_add(me, me->name,
					    lseg, lseg + locks->sh_size,
					    text, text_end);
	}

	if (orc && orc_ip)
		unwind_module_init(me, (void *)orc_ip->sh_addr, orc_ip->sh_size,
				   (void *)orc->sh_addr, orc->sh_size);

	return 0;
}

void module_arch_cleanup(struct module *mod)
{
	alternatives_smp_module_del(mod);
}
