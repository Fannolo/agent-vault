#if defined(__linux__)
#define _GNU_SOURCE
#endif
#include "CAgentVaultSocket.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int fill_address(const char *path, struct sockaddr_un *address, socklen_t *length) {
    size_t count = strlen(path);
    if (count == 0 || count >= sizeof(address->sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    memcpy(address->sun_path, path, count + 1);
    *length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + count + 1);
    return 0;
}

static int close_preserving_errno(int fd) {
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
}

#if !defined(__linux__)
// Apple socket() and accept() take no close-on-exec flag. The gap matters only to a concurrent
// fork/exec; the macOS product transport is XPC, and these sockets serve tests and development.
static int prepare(int fd) {
    int flags = fcntl(fd, F_GETFL);
    int one = 1;
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) != 0
        || setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) != 0) {
        return close_preserving_errno(fd);
    }
    return fd;
}
#endif

static int new_socket(void) {
#if defined(__linux__)
    return socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#else
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    return fd < 0 ? -1 : prepare(fd);
#endif
}

int av_socket_bind(const char *path) {
    struct sockaddr_un address;
    socklen_t length;
    if (fill_address(path, &address, &length) != 0) return -1;
    int fd = new_socket();
    if (fd < 0) return -1;
    if (bind(fd, (const struct sockaddr *)&address, length) != 0) return close_preserving_errno(fd);
    return fd;
}

int av_socket_listen(int fd, int backlog) { return listen(fd, backlog); }

int av_socket_accept(int listen_fd) {
#if defined(__linux__)
    return accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
    int fd = accept(listen_fd, NULL, NULL);
    return fd < 0 ? -1 : prepare(fd);
#endif
}

int av_socket_connect(const char *path, int *in_progress) {
    struct sockaddr_un address;
    socklen_t length;
    *in_progress = 0;
    if (fill_address(path, &address, &length) != 0) return -1;
    int fd = new_socket();
    if (fd < 0) return -1;
    if (connect(fd, (const struct sockaddr *)&address, length) == 0) return fd;
    if (errno == EINPROGRESS) {
        *in_progress = 1;
        return fd;
    }
    return close_preserving_errno(fd);
}

int av_socket_connect_result(int fd) {
    int value = 0;
    socklen_t length = sizeof(value);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &length) != 0) return errno;
    return value;
}

int av_socket_peer_uid(int fd, uint32_t *uid) {
#if defined(__linux__)
    struct ucred credentials;
    socklen_t length = sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0) return -1;
    if (length != sizeof(credentials)) {
        errno = EPROTO;
        return -1;
    }
    *uid = (uint32_t)credentials.uid;
    return 0;
#else
    uid_t user;
    gid_t group;
    if (getpeereid(fd, &user, &group) != 0) return -1;
    *uid = (uint32_t)user;
    return 0;
#endif
}

ssize_t av_socket_send(int fd, const void *bytes, size_t count) {
#if defined(__linux__)
    return send(fd, bytes, count, MSG_NOSIGNAL);
#else
    return send(fd, bytes, count, 0);
#endif
}

ssize_t av_socket_recv(int fd, void *bytes, size_t count) { return recv(fd, bytes, count, 0); }

int av_socket_shutdown(int fd) { return shutdown(fd, SHUT_RDWR); }

int av_socket_wait(int fd, int wake_fd, int events, int timeout_ms) {
    struct pollfd entries[2];
    nfds_t count = 1;
    entries[0].fd = fd;
    entries[0].events = (short)(((events & AV_WAIT_READ) ? POLLIN : 0) | ((events & AV_WAIT_WRITE) ? POLLOUT : 0));
    entries[0].revents = 0;
    if (wake_fd >= 0) {
        entries[1].fd = wake_fd;
        entries[1].events = POLLIN;
        entries[1].revents = 0;
        count = 2;
    }
    int ready = poll(entries, count, timeout_ms);
    if (ready < 0) return -1;
    if (ready == 0) return AV_WAIT_TIMEOUT;
    if (count == 2 && entries[1].revents != 0) return AV_WAIT_WOKEN;
    return AV_WAIT_READY;
}

int av_socket_pipe(int fds[2]) {
#if defined(__linux__)
    return pipe2(fds, O_CLOEXEC | O_NONBLOCK);
#else
    if (pipe(fds) != 0) return -1;
    for (int i = 0; i < 2; i++) {
        int flags = fcntl(fds[i], F_GETFL);
        if (flags < 0 || fcntl(fds[i], F_SETFL, flags | O_NONBLOCK) != 0 || fcntl(fds[i], F_SETFD, FD_CLOEXEC) != 0) {
            int saved = errno;
            close(fds[0]);
            close(fds[1]);
            errno = saved;
            return -1;
        }
    }
    return 0;
#endif
}
