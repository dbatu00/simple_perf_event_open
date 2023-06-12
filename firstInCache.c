#include <stdio.h>

#define CACHE_LINE_SIZE 64

int main() {
    unsigned long address = 0x1000; // starting address, it can be any address within the cacheline

    for (int i = 0; i < 16; i++) {
        unsigned long current_address = address + (i * 8);
        printf("Current Address: 0x%lx\n", current_address);
        unsigned long first_address_in_cacheline = current_address & ~(CACHE_LINE_SIZE - 1);
        printf("First Address in Cache Line: 0x%lx\n", first_address_in_cacheline);
    }

    return 0;
}
