// 单元测试：monitor 单实例锁（W7 D1 / G16）
// 编译: make test_instance_lock（见 tests/Makefile）

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

#include "instance_lock.hpp"

// 锁获取冲突：本进程首获成功；fork 子进程以独立 open 描述符抢同一锁
// 应得 EWOULDBLOCK，且锁文件内容可读出持锁方 pid（父进程）。
// （子进程继承父进程静态 lock_fd，故子进程内用原生 open+flock 验证语义，
//   而非重调 AcquireInstanceLock。）
void test_lock_conflict() {
    const std::string path = "/tmp/baseline_guard_test_instance.lock";
    unlink(path.c_str());

    int holder = -1;
    std::string err;
    assert(common::AcquireInstanceLock(path, holder, err));

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        int fd = open(path.c_str(), O_RDWR);
        if (fd < 0)
            _exit(2);
        if (flock(fd, LOCK_EX | LOCK_NB) == 0)
            _exit(3); // 不应抢锁成功
        if (errno != EWOULDBLOCK)
            _exit(4);
        char buf[32] = {0};
        if (read(fd, buf, sizeof(buf) - 1) <= 0)
            _exit(5);
        _exit(atoi(buf) == getppid() ? 0 : 6);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("[PASS] LOCK-001: 锁冲突拒绝第二持有者，锁文件含持锁 pid\n");

    // 幂等：持锁进程重复获取直接成功
    holder = -1;
    assert(common::AcquireInstanceLock(path, holder, err));
    printf("[PASS] LOCK-002: 持锁进程重复获取幂等\n");
}

int main() {
    test_lock_conflict();
    printf("[PASS] ALL test_instance_lock done\n");
    return 0;
}
