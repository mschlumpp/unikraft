/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Badoiu Vlad-Andrei <vlad_andrei.badoiu@upb.ro>
 *          Marco Schlumpp <marco.schlumpp@gmail.com>
 *
 * Copyright (c) 2021, University Politehnica of Bucharest. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdbool.h>
#include <uk/print.h>
#include <uk/assert.h>
#include <uk/essentials.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "kasan_internal.h"
#include <uk/kasan.h>

static int kasan_ready;

static const char *code_name(uint8_t code)
{
	switch (code) {
	case KASAN_CODE_ADDRESSABLE:
		return "addressable";
	case KASAN_CODE_STACK_LEFT:
	case KASAN_CODE_STACK_MID:
	case KASAN_CODE_STACK_RIGHT:
		return "stack buffer-overflow";
	case KASAN_CODE_GLOBAL_OVERFLOW:
		return "global buffer-overflow";
	case KASAN_CODE_KMEM_FREED:
		return "kmem use-after-free";
	case KASAN_CODE_POOL_OVERFLOW:
		return "pool buffer-overflow";
	case KASAN_CODE_POOL_FREED:
		return "pool use-after-free";
	case KASAN_CODE_KMALLOC_OVERFLOW:
		return "buffer-overflow";
	case KASAN_CODE_KMALLOC_FREED:
		return "use-after-free";
	case 1 ... 7:
		return "partial redzone";
	default:
		return "unknown redzone";
	}
}

static void print_legend_key(uint8_t *used_codes, const char *custom,
			     uint8_t code)
{
	const char *key = custom;

	if (used_codes && !used_codes[code]) {
		return;
	}

	if (!key) {
		key = code_name(code);
	}
	uk_pr_crit("%22s: %02x\n", key, code);
}

static void print_shadow_environment_legend(uint8_t *used_codes)
{
	uk_pr_crit("Shadow byte legend (one shadow byte represents 8 "
		   "application bytes):\n");
	print_legend_key(used_codes, NULL, KASAN_CODE_ADDRESSABLE);
	for (int i = 1; i < 8; i++) {
		print_legend_key(used_codes, "partially-addressable", i);
	}
	print_legend_key(used_codes, NULL, KASAN_CODE_STACK_LEFT);
	print_legend_key(used_codes, NULL, KASAN_CODE_STACK_MID);
	print_legend_key(used_codes, NULL, KASAN_CODE_STACK_RIGHT);
	print_legend_key(used_codes, NULL, KASAN_CODE_GLOBAL_OVERFLOW);
	print_legend_key(used_codes, NULL, KASAN_CODE_KMEM_FREED);
	print_legend_key(used_codes, NULL, KASAN_CODE_POOL_OVERFLOW);
	print_legend_key(used_codes, NULL, KASAN_CODE_POOL_FREED);
	print_legend_key(used_codes, NULL, KASAN_CODE_KMALLOC_OVERFLOW);
	print_legend_key(used_codes, NULL, KASAN_CODE_KMALLOC_FREED);
}

static void print_environment_row(uint8_t *used_codes, int shadow_bytes_per_row,
				  uintptr_t row_addr, uintptr_t target)
{
	const char *prefix, *suffix;
	uk_pr_crit("%" PRIxPTR ": ", row_addr);
	for (int col = 0; col < shadow_bytes_per_row; col++) {
		uintptr_t addr = row_addr + (col << KASAN_SHADOW_SCALE_SHIFT);
		uint8_t code = *kasan_md_addr_to_shad(addr);
		used_codes[code] = 1;

		suffix = "";
		if (addr == target) {
			prefix = "[";
			suffix = "]";
		} else if (addr == target + KASAN_SHADOW_SCALE_SIZE
			   && col != 0) {
			prefix = "";
		} else {
			prefix = " ";
		}
		uk_pr_crit("%s%02x%s", prefix, code, suffix);
	}
	uk_pr_crit("\n");
}

static void print_shadow_environment(uint8_t *used_codes, uintptr_t addr)
{
	const int shadow_bytes_per_row = 16;
	const int real_bytes_per_row = shadow_bytes_per_row
				       << KASAN_SHADOW_SCALE_SHIFT;
	const int context_rows = 6;

	uk_pr_crit("Shadow bytes around buggy address:\n");

	uintptr_t aligned_addr = addr & ~((real_bytes_per_row)-1);
	for (int row = -context_rows; row < context_rows; row++) {
		uintptr_t row_addr = aligned_addr + row * real_bytes_per_row;
		if (!kasan_md_addr_supported(row_addr))
			continue;
		print_environment_row(used_codes, shadow_bytes_per_row,
				      row_addr, addr & ~KASAN_SHADOW_MASK);
	}
}

/* Check whether all bytes from range [addr, addr + size) are mapped to
 * a single shadow byte
 */
static inline bool
access_within_shadow_byte(uintptr_t addr, size_t size) {
	return (addr >> KASAN_SHADOW_SCALE_SHIFT) ==
		((addr + size - 1) >> KASAN_SHADOW_SCALE_SHIFT);
}

static inline bool
shadow_1byte_isvalid(uintptr_t addr, uint8_t *code) {
	int8_t shadow_val = (int8_t)*kasan_md_addr_to_shad(addr);
	int8_t last = addr & KASAN_SHADOW_MASK;

	if (likely(shadow_val == 0 || last < shadow_val))
		return true;
	*code = shadow_val;
	return false;
}

static inline bool
shadow_2byte_isvalid(uintptr_t addr, uint8_t *code) {
	if (!access_within_shadow_byte(addr, 2))
		return shadow_1byte_isvalid(addr, code) &&
			shadow_1byte_isvalid(addr + 1, code);

	int8_t shadow_val = *kasan_md_addr_to_shad(addr);
	int8_t last = (addr + 1) & KASAN_SHADOW_MASK;

	if (likely(shadow_val == 0 || last < shadow_val))
		return true;
	*code = shadow_val;
	return false;
}

static inline bool
shadow_4byte_isvalid(uintptr_t addr, uint8_t *code) {
	if (!access_within_shadow_byte(addr, 4))
		return shadow_2byte_isvalid(addr, code) &&
			shadow_2byte_isvalid(addr + 2, code);

	int8_t shadow_val = *kasan_md_addr_to_shad(addr);
	int8_t last = (addr + 3) & KASAN_SHADOW_MASK;

	if (likely(shadow_val == 0 || last < shadow_val))
		return true;
	*code = shadow_val;
	return false;
}

static inline bool
shadow_8byte_isvalid(uintptr_t addr, uint8_t *code)
{
	if (!access_within_shadow_byte(addr, 8))
		return shadow_4byte_isvalid(addr, code) &&
			shadow_4byte_isvalid(addr + 4, code);

	int8_t shadow_val = *kasan_md_addr_to_shad(addr);
	int8_t last = (addr + 7) & KASAN_SHADOW_MASK;

	if (likely(shadow_val == 0 || last < shadow_val))
		return true;
	*code = shadow_val;
	return false;
}

static inline bool
shadow_Nbyte_isvalid(uintptr_t addr, size_t size, uint8_t *code)
{
		for (size_t i = 0; i < size; i++)
			if (unlikely(!shadow_1byte_isvalid(addr + i, code)))
				return false;
		return true;
}

static inline void
shadow_check(uintptr_t addr, size_t size, bool read)
{
	if (unlikely(!kasan_ready))
		return;
	if (unlikely(!kasan_md_addr_supported(addr)))
		return;

	uint8_t code = 0;
	bool valid = true;

	if (__builtin_constant_p(size)) {
		switch (size) {
		case 1:
			valid = shadow_1byte_isvalid(addr, &code);
			break;
		case 2:
			valid = shadow_2byte_isvalid(addr, &code);
			break;
		case 4:
			valid = shadow_4byte_isvalid(addr, &code);
			break;
		case 8:
			valid = shadow_8byte_isvalid(addr, &code);
			break;
		}
	} else {
		valid = shadow_Nbyte_isvalid(addr, size, &code);
	}

	if (unlikely(!valid)) {
		// Use one byte per code for simplicity
		uint8_t used_codes[256];
		__builtin_memset(used_codes, 0, sizeof(used_codes));

		uk_pr_crit("===========KernelAddressSanitizer===========\n"
			   "ERROR:\n"
			   "* invalid access to address %p\n"
			   "* %s of size %lu\n"
			   "* redzone code 0x%x (%s)\n"
			   "============================================\n",
			   (void *)addr, (read ? "read" : "write"), size, code,
			   code_name(code));
		uk_pr_crit("\n");
		print_shadow_environment(used_codes, addr);
		print_shadow_environment_legend(used_codes);
		UK_CRASH("address sanitizer detected an error\n");
	}
}

/*
 * Memory is divided into 8-byte blocks aligned to 8-byte boundary. Each block
 * has corresponding descriptor byte in the shadow memory. You can mark each
 * block as valid (0x00) or invalid (0xF1 - 0xFF). Blocks can be partially valid
 * (0x01 - 0x07) - i.e. prefix is valid, suffix is invalid.  Other variants are
 * NOT POSSIBLE! Thus `addr` and `total` must be block aligned.
 */
void kasan_mark(const void *addr, size_t valid, size_t total, uint8_t code)
{
	UK_ASSERT(is_aligned(addr, KASAN_SHADOW_SCALE_SIZE));
	UK_ASSERT(is_aligned(total, KASAN_SHADOW_SCALE_SIZE));
	UK_ASSERT(valid <= total);

	int8_t *shadow = kasan_md_addr_to_shad((uintptr_t)addr);
	int8_t *end = shadow + total / KASAN_SHADOW_SCALE_SIZE;

	/* Valid bytes. */
	size_t len = valid / KASAN_SHADOW_SCALE_SIZE;

	__builtin_memset(shadow, 0, len);
	shadow += len;

	/* At most one partially valid byte. */
	if (valid & KASAN_SHADOW_MASK)
		*shadow++ = valid & KASAN_SHADOW_MASK;

	/* Invalid bytes. */
	if (shadow < end)
		__builtin_memset(shadow, code, end - shadow);
}

void kasan_mark_valid(const void *addr, size_t size)
{
	kasan_mark(addr, size, size, 0);
}

void kasan_mark_invalid(const void *addr, size_t size, uint8_t code)
{
	kasan_mark(addr, 0, size, code);
}

void *shadow_mem_base;

void init_kasan(void *base)
{
	shadow_mem_base = base;
	/* Set entire shadow memory to zero */
	kasan_mark_valid((const void *)KASAN_MD_SANITIZED_START,
			KASAN_MD_SANITIZED_SIZE);
	/* KASAN is ready to check for errors! */
	kasan_ready = 1;
}

#define DEFINE_ASAN_LOAD_STORE(size)					\
void __asan_load##size##_noabort(uintptr_t addr)			\
{									\
	shadow_check(addr, size, true);					\
}									\
void __asan_store##size##_noabort(uintptr_t addr)			\
{									\
	shadow_check(addr, size, false);				\
}


#define DEFINE_ASAN_LOAD_STORE_CLANG(size)				\
void __asan_report_load##size##_noabort(uintptr_t addr)			\
{									\
	shadow_check(addr, size, true);					\
}									\
void __asan_report_store##size##_noabort(uintptr_t addr)		\
{									\
	shadow_check(addr, size, false);				\
}

DEFINE_ASAN_LOAD_STORE(1);
DEFINE_ASAN_LOAD_STORE(2);
DEFINE_ASAN_LOAD_STORE(4);
DEFINE_ASAN_LOAD_STORE(8);
DEFINE_ASAN_LOAD_STORE(16);

DEFINE_ASAN_LOAD_STORE_CLANG(1);
DEFINE_ASAN_LOAD_STORE_CLANG(2);
DEFINE_ASAN_LOAD_STORE_CLANG(4);
DEFINE_ASAN_LOAD_STORE_CLANG(8);
DEFINE_ASAN_LOAD_STORE_CLANG(16);

// for GCC
void __asan_loadN_noabort(uintptr_t addr, size_t size)
{
	shadow_check(addr, size, true);
}

void __asan_storeN_noabort(uintptr_t addr, size_t size)
{
	shadow_check(addr, size, false);
}

// for clang
void __asan_report_load_n_noabort(uintptr_t addr, size_t size)
{
	shadow_check(addr, size, true);
}
void __asan_report_store_n_noabort(uintptr_t addr, size_t size)
{
	shadow_check(addr, size, false);
}

/* TODO: Called at the end of every function marked as "noreturn".
 * Performs cleanup of the current stack's shadow memory to prevent false
 * positives.
 */
void __asan_handle_no_return(void)
{
}

void __asan_register_globals(struct __asan_global *globals, uintptr_t n)
{

	for (size_t i = 0; i < n; i++)
		kasan_mark((void *)globals[i].beg, globals[i].size,
				globals[i].size_with_redzone,
				KASAN_CODE_GLOBAL_OVERFLOW);
}


void __asan_unregister_globals(uintptr_t globals __unused, uintptr_t n __unused)
{
}

void __asan_alloca_poison(uintptr_t addr, uintptr_t size)
{
	void *left_redzone = (int8_t *)addr - KASAN_ALLOCA_REDZONE_SIZE;
	size_t size_with_mid_redzone = ALIGN_UP(size, KASAN_ALLOCA_REDZONE_SIZE);
	void *right_redzone = (int8_t *)addr + size_with_mid_redzone;

	kasan_mark_invalid(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
			KASAN_CODE_STACK_LEFT);
	kasan_mark((void *)addr, size, size_with_mid_redzone,
			KASAN_CODE_STACK_MID);
	kasan_mark_invalid(right_redzone, KASAN_ALLOCA_REDZONE_SIZE,
			KASAN_CODE_STACK_RIGHT);
}

void __asan_allocas_unpoison(uintptr_t begin, uintptr_t size)
{
	kasan_mark_valid((void *)begin, size);
}

#ifdef __cplusplus
}
#endif
