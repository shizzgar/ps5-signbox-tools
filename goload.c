/* SPDX-License-Identifier: MIT */
/* In-process loader for a Go program built for the PS5 (GOOS=freebsd,
 * -buildmode=pie, internal linking).
 *
 * The SDK crt has already widened the address range that is allowed to issue
 * syscalls, so the Go runtime can use its own raw SYSCALL instructions. All
 * that is left is to map the image, relocate it, and enter it the way the
 * FreeBSD kernel would: %rdi pointing at argc/argv/envp/auxv. */

#include <elf.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/socket.h>

#include <ps5/kernel.h>

#include "goload.h"

#define PS5_PAGE_SIZE 0x4000ul
#define PAGE_TRUNC(x) ((x) & ~(PS5_PAGE_SIZE - 1))
#define PAGE_ROUND(x) PAGE_TRUNC((x) + PS5_PAGE_SIZE - 1)

#define GO_STACK_SIZE (1ul << 20)

#ifndef AT_PAGESZ
#define AT_PAGESZ 6
#endif
#ifndef AT_NULL
#define AT_NULL 0
#endif

void goload_enter(uintptr_t entry, uintptr_t *args, void *stack_top) __attribute__((noreturn));

/* Switch to the new stack and jump to the Go entry point. Never returns. */
__asm__(".intel_syntax noprefix\n"
        ".text\n"
        ".global goload_enter\n"
        ".type goload_enter, @function\n"
        "goload_enter:\n"
        "  mov rax, rdi\n"
        "  mov rdi, rsi\n"
        "  mov rsp, rdx\n"
        "  xor ebp, ebp\n"
        "  jmp rax\n"
        ".att_syntax prefix\n");

#define LOAD_ERROR(message) ((void)write(STDERR_FILENO, message "\n", sizeof(message)))

static int
image_check(const uint8_t *image, size_t size) {
  const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)image;

  if (size < sizeof(*ehdr) || memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
    return -1;
  }
  if (ehdr->e_type != ET_DYN || ehdr->e_machine != EM_X86_64) {
    return -1;
  }
  if (ehdr->e_phoff + (size_t)ehdr->e_phnum * sizeof(Elf64_Phdr) > size) {
    return -1;
  }
  return 0;
}

int
goload_run_managed(const uint8_t *image, size_t size, char *const argv[],
                   char *const envp[], int control, int control_slot) {
  const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)image;
  const Elf64_Phdr *phdr = (const Elf64_Phdr *)(image + ehdr->e_phoff);
  const Elf64_Dyn *dyn = 0;
  const Elf64_Rela *rela = 0;
  size_t relasz = 0;
  uintptr_t min_vaddr = UINTPTR_MAX;
  uintptr_t max_vaddr = 0;
  uintptr_t bias;
  uint8_t *base;
  uint8_t *stack;
  uintptr_t *sp;
  int argc = 0;
  int envc = 0;

  if (image_check(image, size)) {
    LOAD_ERROR("goload: the embedded program is not a relocatable x86-64 ELF image");
    return -1;
  }

  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type != PT_LOAD || !phdr[i].p_memsz) {
      continue;
    }
    if (phdr[i].p_offset + phdr[i].p_filesz > size) {
      LOAD_ERROR("goload: the embedded program is truncated");
      return -1;
    }
    if (phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }
    if (phdr[i].p_vaddr + phdr[i].p_memsz > max_vaddr) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }
  if (min_vaddr >= max_vaddr) {
    LOAD_ERROR("goload: the embedded program has no loadable segments");
    return -1;
  }
  min_vaddr = PAGE_TRUNC(min_vaddr);
  max_vaddr = PAGE_ROUND(max_vaddr);

  base = mmap(0, max_vaddr - min_vaddr, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED) {
    LOAD_ERROR("goload: cannot allocate memory for the program");
    return -1;
  }
  bias = (uintptr_t)base - min_vaddr;

  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD && phdr[i].p_filesz) {
      memcpy((void *)(bias + phdr[i].p_vaddr), image + phdr[i].p_offset, phdr[i].p_filesz);
    } else if (phdr[i].p_type == PT_DYNAMIC) {
      dyn = (const Elf64_Dyn *)(bias + phdr[i].p_vaddr);
    }
  }

  /* The Go linker only emits R_X86_64_RELATIVE for an internally linked PIE. */
  for (; dyn && dyn->d_tag != DT_NULL; dyn++) {
    if (dyn->d_tag == DT_RELA) {
      rela = (const Elf64_Rela *)(bias + dyn->d_un.d_ptr);
    } else if (dyn->d_tag == DT_RELASZ) {
      relasz = dyn->d_un.d_val;
    }
  }
  for (size_t i = 0; rela && i < relasz / sizeof(*rela); i++) {
    if (ELF64_R_TYPE(rela[i].r_info) != R_X86_64_RELATIVE) {
      LOAD_ERROR("goload: unsupported relocation type");
      return -1;
    }
    *(uintptr_t *)(bias + rela[i].r_offset) = bias + rela[i].r_addend;
  }

  /* Segments are 4 KiB aligned but the PS5 uses 16 KiB pages, so protection
   * is applied to whole pages: executable ones become R+X, the rest stays
   * R+W. A page shared by text and read-only data ends up executable, which
   * is harmless. */
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type != PT_LOAD || !(phdr[i].p_flags & PF_X)) {
      continue;
    }
    uintptr_t start = PAGE_TRUNC(bias + phdr[i].p_vaddr);
    uintptr_t end = PAGE_ROUND(bias + phdr[i].p_vaddr + phdr[i].p_memsz);
    /* kernel_mprotect rewrites the protection of the whole kernel map entry
     * that contains the address, so first let a regular mprotect split the
     * text range off into an entry of its own. */
    if (mprotect((void *)start, end - start, PROT_READ)) {
      LOAD_ERROR("goload: mprotect failed");
      return -1;
    }
    if (kernel_mprotect(-1, start, end - start, PROT_READ | PROT_EXEC)) {
      LOAD_ERROR("goload: could not make the program executable (kernel_mprotect failed)");
      return -1;
    }
  }

  stack = mmap(0, GO_STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED) {
    LOAD_ERROR("goload: cannot allocate memory for the stack");
    return -1;
  }

  while (argv && argv[argc]) {
    argc++;
  }
  while (envp && envp[envc]) {
    envc++;
  }

  /* argc, argv[], NULL, envp[], NULL, auxv pairs, AT_NULL */
  sp = (uintptr_t *)(stack + GO_STACK_SIZE);
  sp -= 1 + (argc + 1) + (envc + 1) + 4;
  sp = (uintptr_t *)((uintptr_t)sp & ~0xful);

  uintptr_t *p = sp;
  *p++ = (uintptr_t)argc;
  for (int i = 0; i < argc; i++) {
    *p++ = (uintptr_t)argv[i];
  }
  *p++ = 0;
  for (int i = 0; i < envc; i++) {
    *p++ = (uintptr_t)envp[i];
  }
  *p++ = 0;
  *p++ = AT_PAGESZ;
  *p++ = PS5_PAGE_SIZE;
  *p++ = AT_NULL;
  *p++ = 0;

  const uintptr_t free_start = PAGE_ROUND((uintptr_t)image);
  const uintptr_t free_end = PAGE_TRUNC((uintptr_t)image + size);
  if (free_end > free_start) {
    madvise((void *)free_start, free_end - free_start, MADV_FREE);
  }
  if (dup2(control, control_slot) < 0 || send(control_slot, "L", 1, 0) != 1) {
    LOAD_ERROR("goload: could not pass the panel connection to Go");
    return -1;
  }
  if (control != control_slot)
    close(control);
  goload_enter(bias + ehdr->e_entry, sp, sp);
}
