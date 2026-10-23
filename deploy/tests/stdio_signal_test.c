#include "CAgentVaultStdio.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

/* Standalone process: default SIGPIPE must not terminate an ordinary failed write. */
int main(void) {
    struct sigaction action = {0}, after;
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGPIPE, &action, NULL) != 0) return 1;
    int descriptors[2];
    if (pipe(descriptors) != 0) return 2;
    close(descriptors[0]);
#if defined(__APPLE__)
    if (fcntl(descriptors[1], F_SETNOSIGPIPE, 1) != 0) return 3;
#endif
    sigset_t before, mask;
    if (pthread_sigmask(SIG_BLOCK, NULL, &before) != 0) return 4;
    if (av_stdio_write(descriptors[1], "x", 1) != -1 || errno != EPIPE) return 5;
    if (pthread_sigmask(SIG_BLOCK, NULL, &mask) != 0 ||
        sigismember(&before, SIGPIPE) != sigismember(&mask, SIGPIPE)) return 6;
    if (sigaction(SIGPIPE, NULL, &after) != 0 || after.sa_handler != SIG_DFL) return 7;
#if defined(__linux__)
    /* An earlier caller-owned pending signal must survive our write. */
    sigset_t blocked, previous, pending;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &blocked, &previous) != 0) return 8;
    if (raise(SIGPIPE) != 0) return 9;
    if (av_stdio_write(descriptors[1], "x", 1) != -1 || errno != EPIPE) return 10;
    if (sigpending(&pending) != 0 || sigismember(&pending, SIGPIPE) != 1) return 11;
    int received;
    if (sigwait(&blocked, &received) != 0 || received != SIGPIPE) return 12;
    if (pthread_sigmask(SIG_SETMASK, &previous, NULL) != 0) return 13;
#endif
    close(descriptors[1]);
    return 0;
}
