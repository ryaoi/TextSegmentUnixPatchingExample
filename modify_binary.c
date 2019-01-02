#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>

#define PAGESIZE 4096

#define _BUFFER_SIZE 89
uint8_t buffer[PAGESIZE] = {
  0x9c, 0x55, 0x54, 0x50, 0x53, 0x51, 0x52, 0x57, 0x56, 0x41,
  0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41,
  0x56, 0x41, 0x57, 0xeb, 0x2e, 0x5e, 0xbf, 0x01, 0x00, 0x00,
  0x00, 0xba, 0x0d, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00,
  0x00, 0x0f, 0x05, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41,
  0x5c, 0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x5e, 0x5f, 0x5a,
  0x59, 0x5b, 0x58, 0x5c, 0x5d, 0x9d, 0xe9, 0x46, 0xff, 0xff,
  0xff, 0xe8, 0xcd, 0xff, 0xff, 0xff, 0x48, 0x65, 0x6c, 0x6c,
  0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a
};

size_t newoep = 0;
size_t oep = 0;
size_t insertion_offset = 0;
size_t last_sh_offset = 0;

static void modify_payload()
{
    // for PIE executables 0x47
    int result = (oep - newoep) - 0x47;
    memcpy(&buffer[67], &result, sizeof(int));
}

static void modify_programheader(void *ptr)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	int found = 0;

	ehdr = (Elf64_Ehdr *)ptr;
    shdr = (Elf64_Shdr *)((ptr + ehdr->e_shoff));
	phdr = (Elf64_Phdr *)((ptr + ehdr->e_phoff));

	for (int index = 0;index < ehdr->e_phnum;index++)
	{
	    if (phdr->p_type == PT_LOAD && found == 0)
	    {
	        newoep = phdr->p_filesz + phdr->p_vaddr;
            insertion_offset = phdr->p_offset + phdr->p_filesz;
            phdr->p_filesz += _BUFFER_SIZE;
            phdr->p_memsz += _BUFFER_SIZE;
	        found = 1;
	    }
        else if (found == 1 && (phdr->p_type == PT_LOAD || phdr->p_type == PT_DYNAMIC\
                || phdr->p_type == PT_GNU_RELRO))
            phdr->p_offset += PAGESIZE;
        phdr++;
	}
}

static void modify_sectionheader(void *ptr)
{
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
	Elf64_Shdr *prev_shdr = NULL;
	int found = 0;

	ehdr = (Elf64_Ehdr *)ptr;
    shdr = (Elf64_Shdr *)((ptr + ehdr->e_shoff));
    for (int index = 0; index < ehdr->e_shnum; index++)
    {
        if (prev_shdr != NULL && shdr->sh_type == SHT_INIT_ARRAY)
        {
            prev_shdr->sh_size += _BUFFER_SIZE;
            found = 1;
        }
        if (found == 1)
        {
            shdr->sh_offset += PAGESIZE;
        }
        prev_shdr = shdr;
        shdr++;
    }

}

static void modify_header(void *ptr)
{
    Elf64_Ehdr *ehdr;

    ehdr = (Elf64_Ehdr *)ptr;

    oep = ehdr->e_entry;
    ehdr->e_entry = newoep;
    ehdr->e_shoff += PAGESIZE;
}

static void inject_code(void *ptr, size_t filesize)
{
    memmove(ptr + insertion_offset + PAGESIZE, ptr + insertion_offset, filesize - insertion_offset);
    memcpy(ptr + insertion_offset, buffer, PAGESIZE);
}

static inline void print_error_then_exit()
{
        perror("[-] Error ");
        exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    struct stat file;
    void        *filemap;
    void        *outputfilemap;
    int fd;

    if (argc < 3)
    {
        dprintf(2, "./%s <binary> <outputname>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    fd = open(argv[1], O_RDWR);
    if (fd == -1)
        print_error_then_exit();
    if ((lstat(argv[1], &file)) < 0)
        print_error_then_exit();
    filemap = mmap(0, (file.st_size), PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    outputfilemap = mmap(0, file.st_size + PAGESIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (filemap < 0 || outputfilemap < 0)
        print_error_then_exit();
    memcpy(outputfilemap, filemap, file.st_size);

    modify_programheader(outputfilemap);
    modify_sectionheader(outputfilemap);
    modify_header(outputfilemap);
    modify_payload();
    inject_code(outputfilemap, file.st_size);

    if ((close(fd)) < 0)
        print_error_then_exit();
    fd = open(argv[2], O_RDWR | O_CREAT| O_TRUNC, 0755);
    if (fd == -1)
        print_error_then_exit();
    write(fd, outputfilemap, file.st_size + PAGESIZE);
    if ((close(fd)) < 0)
        print_error_then_exit();
    if ((munmap(filemap, file.st_size)) < 0)
        print_error_then_exit();
    if ((munmap(outputfilemap, file.st_size + PAGESIZE)) < 0)
        print_error_then_exit();
    return (0);
}
