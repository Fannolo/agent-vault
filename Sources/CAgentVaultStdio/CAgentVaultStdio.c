#include "CAgentVaultStdio.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

ssize_t av_stdio_write(int fd, const void *buffer, size_t count) {
#if defined(__linux__)
    sigset_t blocked, previous, pending;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    int result = pthread_sigmask(SIG_BLOCK, &blocked, &previous);
    if (result != 0) { errno = result; return -1; }
    if (sigpending(&pending) != 0) {
        int saved = errno;
        pthread_sigmask(SIG_SETMASK, &previous, NULL);
        errno = saved;
        return -1;
    }
    int already_pending = sigismember(&pending, SIGPIPE);
    ssize_t written = write(fd, buffer, count);
    int saved = errno;
    if (written < 0 && saved == EPIPE && !already_pending) {
        const struct timespec immediate = {0, 0};
        while (sigtimedwait(&blocked, NULL, &immediate) < 0 && errno == EINTR) {}
    }
    pthread_sigmask(SIG_SETMASK, &previous, NULL);
    errno = saved;
    return written;
#else
    /* Darwin callers set F_SETNOSIGPIPE on the descriptor before use. */
    return write(fd, buffer, count);
#endif
}
