// 单元测试：monitor 单实例锁（W7 D1 / G16）
// 编译: make test_instance_lock（见 tests/Makefile）

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <signal.h>
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

// 不同锁路径并存（--lock-path 云上双实例场景）：子进程持锁 A，检查方对
// 另一路径 B 抢锁应成功，对 A 抢锁仍应被拒。
// （父进程静态 lock_fd 已被 LOCK-001 占用，AcquireInstanceLock 幂等语义下
//   无法在同进程再持第二把锁，故持锁方用原生 open+flock。）
void test_lock_path_override() {
    const std::string path_a = "/tmp/baseline_guard_test_instance_a.lock";
    const std::string path_b = "/tmp/baseline_guard_test_instance_b.lock";
    unlink(path_a.c_str());
    unlink(path_b.c_str());

    pid_t holder = fork();
    assert(holder >= 0);
    if (holder == 0) {
        int fd = open(path_a.c_str(), O_RDWR | O_CREAT, 0644);
        if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0)
            _exit(2);
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "%d\n", getpid());
        if (write(fd, buf, static_cast<size_t>(n)) < 0)
            _exit(3);
        sleep(3);   // 持锁等待检查方；fd 不关闭
        _exit(0);
    }
    // 等持锁方就绪（锁文件写入其 pid）
    for (int i = 0; i < 50; i++) {
        char buf[32] = {0};
        int fd = open(path_a.c_str(), O_RDWR);
        if (fd >= 0) {
            ssize_t rn = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (rn > 0 && atoi(buf) == holder)
                break;
        }
        usleep(100000);
    }

    pid_t checker = fork();
    assert(checker >= 0);
    if (checker == 0) {
        int fd_b = open(path_b.c_str(), O_RDWR | O_CREAT, 0644);
        if (fd_b < 0 || flock(fd_b, LOCK_EX | LOCK_NB) != 0)
            _exit(4); // 不同锁路径：应抢锁成功（双实例并存）
        int fd_a = open(path_a.c_str(), O_RDWR);
        if (fd_a < 0 || flock(fd_a, LOCK_EX | LOCK_NB) == 0)
            _exit(5); // 同一锁路径：应仍被拒
        _exit(errno == EWOULDBLOCK ? 0 : 6);
    }
    int status = 0;
    assert(waitpid(checker, &status, 0) == checker);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    kill(holder, SIGTERM);   // sleep 兜底回收
    waitpid(holder, &status, 0);
    printf("[PASS] LOCK-003: 不同 lock-path 双实例并存、同路径仍互斥\n");
}

int main() {
    test_lock_conflict();
    test_lock_path_override();
    printf("[PASS] ALL test_instance_lock done\n");
    return 0;
}
