#include "instance_lock.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace common {

bool AcquireInstanceLock(const std::string &lock_path, int &holder_pid, std::string &err) {
    // 进程级持有：fd 永不关闭，进程退出（含 kill -9）内核自动释放 flock
    static int lock_fd = -1;
    if (lock_fd >= 0)
        return true;

    holder_pid = -1;
    err.clear();
    int fd = open(lock_path.c_str(), O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        err = std::strerror(errno);
        return false;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK) {
            char buf[32] = {0};
            if (read(fd, buf, sizeof(buf) - 1) > 0)
                holder_pid = atoi(buf);
        } else {
            err = std::strerror(errno);
        }
        close(fd);
        return false;
    }
    if (ftruncate(fd, 0) == 0) {
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "%d\n", getpid());
        if (write(fd, buf, static_cast<size_t>(n)) < 0) { /* pid 仅用于报错提示，写失败不影响锁 */ }
    }
    lock_fd = fd;
    return true;
}

} // namespace common
