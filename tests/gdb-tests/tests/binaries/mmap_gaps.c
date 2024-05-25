#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void break_here(void) {}

#define ADDR (void *)0xcafe0000
#define PGSZ 0x1000

int main(void) {
    // We want to allocate multiple adjacent regions, in confirm that vmmap
    // --gaps detects them properly. So we want multiple adjacent allocation,
    // unmapped holes, as well as some guard pages with no permissions.

    uint64_t address = (uint64_t)ADDR;
    void    *p;

    p = mmap((void *)address, PGSZ, PROT_READ,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (-1 == (int64_t)p) {
        printf("Failed to map fixed address at %p\n", (void *)address);
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    address += PGSZ;

    p = mmap((void *)address, PGSZ, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (-1 == (int64_t)p) {
        printf("Failed to map fixed address at %p\n", (void *)address);
        perror("mmap");

        exit(EXIT_FAILURE);
    }
    address += PGSZ;

    // GUARD page
    p = mmap((void *)address, PGSZ, PROT_NONE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (-1 == (int64_t)p) {
        printf("Failed to map fixed address at %p\n", (void *)address);
        perror("mmap");

        exit(EXIT_FAILURE);
    }
    address += PGSZ;
    mprotect(p, 0x1000, PROT_NONE);
    p = mmap((void *)address, PGSZ, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (-1 == (int64_t)p) {
        printf("Failed to map fixed address at %p\n", (void *)address);
        perror("mmap");

        exit(EXIT_FAILURE);
    }
    address += PGSZ;
    break_here();
}
