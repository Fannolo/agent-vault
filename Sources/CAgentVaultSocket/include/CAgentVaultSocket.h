#ifndef C_AGENT_VAULT_SOCKET_H
#define C_AGENT_VAULT_SOCKET_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// Unix stream sockets for the broker transport. Every descriptor returned here is
// close-on-exec and nonblocking, and writes through av_socket_send never raise SIGPIPE.
// Failures return -1 with errno set; nothing here prints or retains caller bytes.

/// A new socket bound to `path`, not yet listening. Refuses a path that does not fit sun_path.
int av_socket_bind(const char *path);
int av_socket_listen(int fd, int backlog);
int av_socket_accept(int listen_fd);
/// A socket connecting to `path`. `*in_progress` is 1 when completion must be awaited with
/// av_socket_wait(..., AV_WAIT_WRITE, ...) and then checked with av_socket_connect_result.
int av_socket_connect(const char *path, int *in_progress);
/// 0 once connected, otherwise the pending socket error.
int av_socket_connect_result(int fd);

/// The kernel-recorded effective UID of the connected peer: SO_PEERCRED on Linux,
/// getpeereid on Apple platforms. Never a value the peer sent.
int av_socket_peer_uid(int fd, uint32_t *uid);

ssize_t av_socket_send(int fd, const void *bytes, size_t count);
ssize_t av_socket_recv(int fd, void *bytes, size_t count);
int av_socket_shutdown(int fd);

enum { AV_WAIT_READ = 1, AV_WAIT_WRITE = 2 };
enum { AV_WAIT_TIMEOUT = 0, AV_WAIT_READY = 1, AV_WAIT_WOKEN = 2 };
/// Waits for `fd`, or for `wake_fd` (ignored when negative) to become readable, which wins.
/// `timeout_ms` < 0 waits indefinitely. EINTR is returned to the caller, which owns the deadline.
int av_socket_wait(int fd, int wake_fd, int events, int timeout_ms);

/// A close-on-exec, nonblocking pipe.
int av_socket_pipe(int fds[2]);

#endif
