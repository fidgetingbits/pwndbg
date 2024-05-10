#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void break_here(void) {}

#define ADDR (void *)0xcafe00000000

int main(void) {
    // We want to allocate multiple adjacent regions, in confirm that vmmap
    // --gaps detects them properly. So we want multiple adjacent allocation,
    // unmapped holes, as well as some guard pages with no permissions.

    void *p1 = mmap(ADDR, 0x1000, PROT_READ | PROT_WRITE,
                    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *p2 = mmap(ADDR + 0x2000, 0x1000, PROT_READ | PROT_WRITE,
                    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *p3 = mmap(ADDR + 0x3000, 0x1000, PROT_NONE,
                    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    break_here();
}
