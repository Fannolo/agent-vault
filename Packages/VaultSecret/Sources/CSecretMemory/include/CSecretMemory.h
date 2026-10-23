#ifndef AGENT_VAULT_SECRET_MEMORY_H
#define AGENT_VAULT_SECRET_MEMORY_H

#include <stddef.h>

void av_secret_clear(void *memory, size_t count);
int av_secret_equal(const void *left, const void *right, size_t count);

#endif
