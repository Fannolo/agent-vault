#ifndef C_AGENT_VAULT_STDIO_H
#define C_AGENT_VAULT_STDIO_H
#include <stddef.h>
#include <sys/types.h>
/* Write without changing the process-wide SIGPIPE disposition. */
ssize_t av_stdio_write(int fd, const void *buffer, size_t count);
#endif
