/*
 * elf_info.h
 *
 * Copyright (C) 2011  NEC Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef _ELF_INFO_H
#define _ELF_INFO_H

#include <elf.h>
#include <sys/types.h>

#define KEXEC_CORE_NOTE_NAME "CORE"
#define KEXEC_CORE_NOTE_NAME_BYTES sizeof(KEXEC_CORE_NOTE_NAME)

#define ERASEINFO_NOTE_NAME		"ERASEINFO"
#define ERASEINFO_NOTE_NAME_BYTES	(sizeof(ERASEINFO_NOTE_NAME))

#define MAX_SIZE_NHDR	MAX(sizeof(Elf64_Nhdr), sizeof(Elf32_Nhdr))

int get_elf64_phdr(int fd, char *filename, int index, Elf64_Phdr *phdr);
int get_elf32_phdr(int fd, char *filename, int index, Elf32_Phdr *phdr);

off_t paddr_to_offset(unsigned long long paddr);
off_t paddr_to_offset2(unsigned long long paddr, off_t hint);
unsigned long long page_head_to_phys_start(unsigned long long head_paddr);
unsigned long long page_head_to_phys_end(unsigned long long head_paddr);
off_t offset_to_pt_load_start(off_t offset);
off_t offset_to_pt_load_end(off_t offset);
unsigned long long vaddr_to_paddr_general(unsigned long long vaddr);
off_t vaddr_to_offset_slow(int fd, char *filename, unsigned long long vaddr);
unsigned long long get_max_paddr(void);
int closest_pt_load(unsigned long long paddr, unsigned long distance);

int page_is_fractional(off_t page_offset);

int get_elf64_ehdr(int fd, char *filename, Elf64_Ehdr *ehdr);
int get_elf32_ehdr(int fd, char *filename, Elf32_Ehdr *ehdr);
int get_elf_info(int fd, char *filename);
void free_elf_info(void);
int get_elf_loads(int fd, char *filename);
int set_kcore_vmcoreinfo(uint64_t vmcoreinfo_addr, uint64_t vmcoreinfo_len);
int get_kcore_dump_loads(void);

int is_elf64_memory(void);
int is_xen_memory(void);

int get_phnum_memory(void);
int get_phdr_memory(int index, Elf64_Phdr *phdr);
off_t get_offset_pt_load_memory(void);
int get_pt_load(int idx,
	unsigned long long *phys_start,
	unsigned long long *phys_end,
	unsigned long long *virt_start,
	unsigned long long *virt_end);
int get_pt_load_extents(int idx,
	unsigned long long *phys_start,
	unsigned long long *phys_end,
	off_t *file_offset,
	off_t *file_size);
unsigned int get_num_pt_loads(void);

void set_nr_cpus(int num);
int get_nr_cpus(void);

int has_pt_note(void);
void set_pt_note(off_t offset, unsigned long size);
void get_pt_note(off_t *offset, unsigned long *size);

int has_vmcoreinfo(void);
void set_vmcoreinfo(off_t offset, unsigned long size);
void get_vmcoreinfo(off_t *offset, unsigned long *size);

int has_vmcoreinfo_xen(void);
void get_vmcoreinfo_xen(off_t *offset, unsigned long *size);
void get_xen_crash_info(off_t *offset, unsigned long *size);

int has_eraseinfo(void);
void get_eraseinfo(off_t *offset, unsigned long *size);
void set_eraseinfo(off_t offset, unsigned long size);

off_t get_max_file_offset(void);

#endif  /* ELF_INFO_H */


