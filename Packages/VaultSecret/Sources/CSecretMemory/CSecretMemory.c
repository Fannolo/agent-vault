#include "CSecretMemory.h"

void av_secret_clear(void *memory, size_t count) {
    volatile unsigned char *bytes = memory;
    while (count > 0) {
        *bytes++ = 0;
        count--;
    }
}
