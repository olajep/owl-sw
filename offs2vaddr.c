/* In an ideal world there should be a way to specify the *file offset* instead
 * of the address to binutils/addr2line. For now roll our own binary that
 * calculates the right address from the Elf headers */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <elf.h>

static bool
elf_p(const void *ptr)
{
	const Elf64_Ehdr *ehdr = ptr;
	return memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0
		/* TODO: Support ELFCLASS32 */
		&& ehdr->e_ident[EI_CLASS] == ELFCLASS64
		&& ehdr->e_version == EV_CURRENT;
}


void usage_and_die(char **argv)
{
	fprintf(stderr, "usage: %s FILE OFFSET\n", argv[0]);
	exit(EXIT_FAILURE);
}

static int
map_file(const char *path, const void **ptr, size_t *size)
{
	const void *mem;
	int fd, err;
	struct stat sb;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return fd;

	err = fstat(fd, &sb);
	if (err < 0)
		return err;

	mem = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED)
		return -1;

	*ptr = mem;
	*size = sb.st_size;

	return fd;
}

static bool
offs2vaddr(const uint8_t *file, unsigned long offs,
	   unsigned long *addr)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Half i;

	ehdr = (Elf64_Ehdr *) &file[0];
	phdr = (Elf64_Phdr *) &file[ehdr->e_phoff];

	for (i = 0; i < ehdr->e_phnum; i++) {
		switch (phdr[i].p_type) {
			default:
				continue;
			case PT_LOAD: case PT_GNU_STACK:
				 break;
		}
		if (phdr[i].p_offset <= offs &&
		    offs - phdr[i].p_offset < phdr[i].p_filesz) {
			Elf64_Off diff;
			diff = offs - phdr[i].p_offset;
			*addr = phdr[i].p_vaddr + diff;
			return true;
		}
	}

	return false;
}

int
main(int argc, char *argv[])
{
	int fd;
	const uint8_t *file;
	size_t size;
	unsigned long offs, addr;

	if (argc != 3)
		usage_and_die(argv);

	fd = map_file(argv[1], (const void **) &file, &size);
	if (fd < 0)
		usage_and_die(argv);

	if (!elf_p(file)) {
		fprintf(stderr, "%s is not  a 64 bit ELF file\n", argv[1]);
		usage_and_die(argv);
	}

	offs = strtoul(argv[2], NULL, 0);
	if (errno) {
		fprintf(stderr, "%s: Cannot parse number\n", argv[2]);
		usage_and_die(argv);
	}

	if (!offs2vaddr(file, offs, &addr)) {
		fprintf(stderr, "%s: Cannot parse ELF headers\n", argv[1]);
		usage_and_die(argv);
	}

	printf("%lx\n", addr);

	munmap((void *) file, size);
	close(fd);

	return 0;
}
