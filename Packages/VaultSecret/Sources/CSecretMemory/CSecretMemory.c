#include "CSecretMemory.h"

void av_secret_clear(void *memory, size_t count) {
    volatile unsigned char *bytes = memory;
    while (count > 0) {
        *bytes++ = 0;
        count--;
    }
}

int av_secret_equal(const void *left, const void *right, size_t count) {
    const volatile unsigned char *a = left;
    const volatile unsigned char *b = right;
    unsigned char difference = 0;
    for (size_t i = 0; i < count; i++) {
        difference |= a[i] ^ b[i];
    }
    return difference == 0;
}
