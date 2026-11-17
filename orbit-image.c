/* SPDX-License-Identifier: MIT */
#include <elf.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "orbit-image.h"

#ifndef R_X86_64_JUMP_SLOT
#define R_X86_64_JUMP_SLOT R_X86_64_JMP_SLOT
#endif

extern const unsigned char orbit_connect_image[], orbit_connect_image_end[];
__asm__(".section .rodata\n"
        ".balign 16\n"
        ".global orbit_connect_image\n"
        "orbit_connect_image:\n"
        ".incbin \"orbit-connect.bin\"\n"
        ".global orbit_connect_image_end\n"
        "orbit_connect_image_end:\n"
        ".text\n");

struct layout {
    const Elf64_Ehdr *header;
    const Elf64_Phdr *programs;
    const Elf64_Shdr *sections;
    size_t dynamic_offset;
    size_t rela_section;
    size_t connect_rela;
    size_t rela_pointer;
    size_t rela_size;
    size_t virtual_end;
};

static int
in_range(size_t total, size_t offset, size_t length) {
    return offset <= total && length <= total - offset;
}

static size_t
align_up(size_t size, size_t alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}

static int
read_headers(const unsigned char *source, size_t size, struct layout *layout) {
    if (size < sizeof(Elf64_Ehdr) || size > 64 * 1024 * 1024)
        return -1;
    const Elf64_Ehdr *header = (const Elf64_Ehdr *)source;
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) || header->e_ident[EI_CLASS] != ELFCLASS64 ||
        header->e_ident[EI_DATA] != ELFDATA2LSB || header->e_type != ET_DYN ||
        header->e_machine != EM_X86_64 || header->e_phentsize != sizeof(Elf64_Phdr) ||
        header->e_shentsize != sizeof(Elf64_Shdr) || header->e_phnum < 2 || header->e_phnum > 32 ||
        header->e_shnum < 2 || header->e_shnum > 128 ||
        header->e_phoff % 8 || header->e_shoff % 8 ||
        !in_range(size, header->e_phoff, header->e_phnum * sizeof(Elf64_Phdr)) ||
        !in_range(size, header->e_shoff, header->e_shnum * sizeof(Elf64_Shdr)))
        return -1;

    layout->header = header;
    layout->programs = (const Elf64_Phdr *)(source + header->e_phoff);
    layout->sections = (const Elf64_Shdr *)(source + header->e_shoff);
    const Elf64_Phdr *dynamic = NULL;
    size_t first = SIZE_MAX, last = 0;
    int entry_valid = 0;
    for (size_t i = 0; i < header->e_phnum; i++) {
        const Elf64_Phdr *segment = &layout->programs[i];
        if (!in_range(size, segment->p_offset, segment->p_filesz) ||
            !in_range(256 * 1024 * 1024, segment->p_vaddr, segment->p_memsz))
            return -1;
        if (segment->p_type == PT_DYNAMIC) {
            if (dynamic || segment->p_offset % 8)
                return -1;
            dynamic = segment;
        }
        if (segment->p_type != PT_LOAD)
            continue;
        if (segment->p_filesz > segment->p_memsz)
            return -1;
        if (segment->p_vaddr < first)
            first = segment->p_vaddr;
        if (segment->p_vaddr + segment->p_memsz > last)
            last = segment->p_vaddr + segment->p_memsz;
        if ((segment->p_flags & PF_X) && segment->p_vaddr <= header->e_entry &&
            header->e_entry - segment->p_vaddr < segment->p_filesz)
            entry_valid = 1;
    }

    if (!entry_valid || first != 0 || !dynamic || !dynamic->p_filesz ||
        dynamic->p_filesz % sizeof(Elf64_Dyn))
        return -1;
    layout->virtual_end = align_up(last, ORBIT_HOOK_PAGE);
    layout->dynamic_offset = dynamic->p_offset;
    const Elf64_Dyn *entries = (const Elf64_Dyn *)(source + dynamic->p_offset);
    size_t count = dynamic->p_filesz / sizeof(*entries);
    size_t rela_address = 0, rela_length = 0;
    for (size_t i = 0; i < count && entries[i].d_tag != DT_NULL; i++) {
        if (entries[i].d_tag == DT_RELA) {
            layout->rela_pointer = i;
            rela_address = entries[i].d_un.d_ptr;
        } else if (entries[i].d_tag == DT_RELASZ) {
            layout->rela_size = i;
            rela_length = entries[i].d_un.d_val;
        } else if (entries[i].d_tag == DT_RELAENT && entries[i].d_un.d_val != sizeof(Elf64_Rela)) {
            return -1;
        }
    }
    if (!rela_address || !rela_length || rela_length % sizeof(Elf64_Rela))
        return -1;
    for (size_t i = 1; i < header->e_shnum; i++) {
        const Elf64_Shdr *section = &layout->sections[i];
        if (section->sh_type == SHT_RELA && section->sh_addr == rela_address &&
            section->sh_size == rela_length && section->sh_link < header->e_shnum &&
            section->sh_offset % 8 == 0 && in_range(size, section->sh_offset, section->sh_size)) {
            layout->rela_section = i;
            return 0;
        }
    }
    return -1;
}

static int
data_slot(const struct layout *layout, uint64_t address) {
    if (address % sizeof(uint64_t))
        return 0;
    for (size_t i = 0; i < layout->header->e_phnum; i++) {
        const Elf64_Phdr *segment = &layout->programs[i];
        if (segment->p_type == PT_LOAD && (segment->p_flags & PF_W) && !(segment->p_flags & PF_X) &&
            address >= segment->p_vaddr && in_range(segment->p_memsz, address - segment->p_vaddr, sizeof(uint64_t)))
            return 1;
    }
    return 0;
}

static int
find_connect(const unsigned char *source, size_t size, struct layout *layout) {
    const Elf64_Shdr *segment = &layout->sections[layout->rela_section];
    const Elf64_Shdr *symbols = &layout->sections[segment->sh_link];
    if (symbols->sh_type != SHT_DYNSYM || symbols->sh_link >= layout->header->e_shnum ||
        symbols->sh_offset % 8 || symbols->sh_size % sizeof(Elf64_Sym) ||
        !in_range(size, symbols->sh_offset, symbols->sh_size))
        return -1;
    const Elf64_Shdr *strings = &layout->sections[symbols->sh_link];
    if (strings->sh_type != SHT_STRTAB || !in_range(size, strings->sh_offset, strings->sh_size))
        return -1;
    const Elf64_Sym *entries = (const Elf64_Sym *)(source + symbols->sh_offset);
    const Elf64_Rela *relocations = (const Elf64_Rela *)(source + segment->sh_offset);
    size_t matches = 0;
    for (size_t i = 0; i < segment->sh_size / sizeof(*relocations); i++) {
        uint32_t type = ELF64_R_TYPE(relocations[i].r_info);
        size_t symbol = ELF64_R_SYM(relocations[i].r_info);
        if ((type != R_X86_64_GLOB_DAT && type != R_X86_64_JUMP_SLOT) ||
            symbol >= symbols->sh_size / sizeof(*entries))
            continue;
        const Elf64_Sym *entry = &entries[symbol];
        if (entry->st_shndx != SHN_UNDEF || !in_range(strings->sh_size, entry->st_name, sizeof("connect")) ||
            memcmp(source + strings->sh_offset + entry->st_name, "connect", sizeof("connect")))
            continue;
        if (relocations[i].r_addend || !data_slot(layout, relocations[i].r_offset))
            return -1;
        layout->connect_rela = i;
        matches++;
    }
    return matches == 1 ? 0 : -1;
}

static int
region_covers(const struct orbit_region *regions, size_t count, uintptr_t address,
              size_t size, unsigned protection) {
    for (size_t i = 0; i < count; i++) {
        const struct orbit_region *region = &regions[i];
        if ((region->protection & protection) == protection && address >= region->start &&
            address < region->end && size <= region->end - address)
            return 1;
    }
    return 0;
}

int
orbit_find_live_import(const unsigned char *source, size_t size,
                       const struct orbit_region *regions, size_t count,
                       int (*read_memory)(void *, uintptr_t, void *, size_t), void *context,
                       uintptr_t *base, uintptr_t *slot) {
    struct layout layout = {0};
    if (read_headers(source, size, &layout) || find_connect(source, size, &layout)) {
        errno = ENOEXEC;
        return -1;
    }
    const Elf64_Phdr *text = NULL;
    for (size_t i = 0; i < layout.header->e_phnum; i++) {
        const Elf64_Phdr *segment = &layout.programs[i];
        if (segment->p_type == PT_LOAD && (segment->p_flags & PF_X) &&
            layout.header->e_entry >= segment->p_vaddr &&
            layout.header->e_entry - segment->p_vaddr < segment->p_filesz) {
            text = segment;
            break;
        }
    }
    enum { SAMPLE_BYTES = 64 };
    if (!text || text->p_filesz < SAMPLE_BYTES * 3) {
        errno = ENOEXEC;
        return -1;
    }
    const uintptr_t text_page = text->p_vaddr & ~(uintptr_t)(ORBIT_HOOK_PAGE - 1);
    size_t entry = layout.header->e_entry - text->p_vaddr;
    if (entry > text->p_filesz - SAMPLE_BYTES)
        entry = text->p_filesz - SAMPLE_BYTES;
    const size_t section_offset = layout.sections[layout.rela_section].sh_offset;
    const Elf64_Rela *relocations = (const Elf64_Rela *)(source + section_offset);
    const uintptr_t connect_offset = relocations[layout.connect_rela].r_offset;
    const size_t samples[] = {entry, text->p_filesz / 2, text->p_filesz - SAMPLE_BYTES};
    uintptr_t found = 0;
    for (size_t i = 0; i < count; i++) {
        const struct orbit_region *region = &regions[i];
        if (!(region->protection & PROT_EXEC) || region->start < text_page + ORBIT_HOOK_PAGE)
            continue;
        uintptr_t candidate = region->start - text_page;
        if (found == candidate || layout.virtual_end > UINTPTR_MAX - candidate ||
            !region_covers(regions, count, candidate + connect_offset, sizeof(uintptr_t), PROT_READ))
            continue;
        size_t sample = 0;
        for (; sample < sizeof(samples) / sizeof(samples[0]); sample++) {
            unsigned char bytes[SAMPLE_BYTES];
            const size_t offset = samples[sample];
            uintptr_t address = candidate + text->p_vaddr + offset;
            if (!region_covers(regions, count, address, sizeof(bytes), PROT_READ | PROT_EXEC) ||
                read_memory(context, address, bytes, sizeof(bytes)) != 0 ||
                memcmp(bytes, source + text->p_offset + offset, sizeof(bytes)))
                break;
        }
        if (sample != sizeof(samples) / sizeof(samples[0]))
            continue;
        if (found) {
            errno = EEXIST;
            return -1;
        }
        found = candidate;
    }
    if (!found) {
        errno = ENOENT;
        return -1;
    }
    *base = found;
    *slot = found + connect_offset;
    return 0;
}

int
orbit_image(const unsigned char *source, size_t source_size, const struct orbit_config *config, int gate,
            unsigned char **image, size_t *image_size) {
    struct layout layout = {0};
    if (read_headers(source, source_size, &layout) || find_connect(source, source_size, &layout)) {
        errno = ENOEXEC;
        return -1;
    }

    const Elf64_Shdr *old_rela = &layout.sections[layout.rela_section];
    const size_t code_offset = align_up(source_size, ORBIT_HOOK_PAGE);
    const size_t code_address = layout.virtual_end;
    const size_t data_offset = code_offset + ORBIT_HOOK_PAGE;
    const size_t data_address = code_address + ORBIT_HOOK_PAGE;
    const size_t blob_size = (size_t)(orbit_connect_image_end - orbit_connect_image);
    if (blob_size != ORBIT_HOOK_PAGE + sizeof(*config)) {
        errno = ENOEXEC;
        return -1;
    }
    const size_t rela_offset = align_up(code_offset + blob_size, 8);
    const size_t rela_address = code_address + (rela_offset - code_offset);
    const size_t rela_size = old_rela->sh_size + (gate ? 2 : 1) * sizeof(Elf64_Rela);
    const size_t ph_offset = rela_offset + rela_size;
    const size_t ph_size = (layout.header->e_phnum + 2) * sizeof(Elf64_Phdr);
    const size_t sh_offset = ph_offset + ph_size;
    const size_t sh_size = layout.header->e_shnum * sizeof(Elf64_Shdr);
    const size_t total = sh_offset + sh_size;

    unsigned char *output = calloc(1, total);
    if (!output)
        return -1;
    memcpy(output, source, source_size);
    memcpy(output + code_offset, orbit_connect_image, blob_size);
    memcpy(output + data_offset, config, sizeof(*config));

    Elf64_Rela *relocations = (Elf64_Rela *)(output + rela_offset);
    memcpy(relocations, source + old_rela->sh_offset, old_rela->sh_size);
    Elf64_Rela *import = &relocations[layout.connect_rela];
    Elf64_Rela *redirect = &relocations[old_rela->sh_size / sizeof(Elf64_Rela)];
    *redirect = (Elf64_Rela){.r_offset = import->r_offset, .r_info = R_X86_64_RELATIVE,
                              .r_addend = code_address};
    import->r_offset = data_address + offsetof(struct orbit_config, connect_function);
    if (gate)
        redirect[1] = (Elf64_Rela){.r_offset = data_address + offsetof(struct orbit_config, boot_entry),
                                  .r_info = R_X86_64_RELATIVE, .r_addend = layout.header->e_entry};

    Elf64_Ehdr *header = (Elf64_Ehdr *)output;
    Elf64_Phdr *programs = (Elf64_Phdr *)(output + ph_offset);
    Elf64_Shdr *sections = (Elf64_Shdr *)(output + sh_offset);
    memcpy(programs, layout.programs, header->e_phnum * sizeof(*programs));
    memcpy(sections, layout.sections, sh_size);
    programs[header->e_phnum++] = (Elf64_Phdr){
        .p_type = PT_LOAD, .p_flags = PF_R | PF_X, .p_offset = code_offset, .p_vaddr = code_address,
        .p_filesz = ORBIT_HOOK_PAGE, .p_memsz = ORBIT_HOOK_PAGE, .p_align = ORBIT_HOOK_PAGE,
    };
    const size_t data_size = ph_offset - data_offset;
    programs[header->e_phnum++] = (Elf64_Phdr){
        .p_type = PT_LOAD, .p_flags = PF_R | PF_W, .p_offset = data_offset, .p_vaddr = data_address,
        .p_filesz = data_size, .p_memsz = align_up(data_size, ORBIT_HOOK_PAGE), .p_align = ORBIT_HOOK_PAGE,
    };
    header->e_phoff = ph_offset;
    header->e_shoff = sh_offset;
    if (gate)
        header->e_entry = code_address + ORBIT_BOOT_ENTRY;
    Elf64_Shdr *rela = &sections[layout.rela_section];
    rela->sh_addr = rela_address;
    rela->sh_offset = rela_offset;
    rela->sh_size = rela_size;
    Elf64_Dyn *dynamic = (Elf64_Dyn *)(output + layout.dynamic_offset);
    dynamic[layout.rela_pointer].d_un.d_ptr = rela_address;
    dynamic[layout.rela_size].d_un.d_val = rela_size;
    *image = output;
    *image_size = total;
    return 0;
}
