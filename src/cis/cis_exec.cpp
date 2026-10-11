#include "cis_exec.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace cis {

bool CommandIsReadOnly(const std::string& cmd, std::string& hit) {
    static const char* kWritePatterns[] = {
        "sed -i",           "sysctl -w",       "sysctl --write",  "systemctl start",
        "systemctl stop",   "systemctl restart", "systemctl reload", "systemctl enable",
        "systemctl disable", "systemctl mask", "chmod",           "chown",
        "chgrp",            "rm -",            " rm ",            "rmdir",
        "mkfs",             "dd if=",          "tee ",            "mount ",
        "umount",           "> /etc",          ">> /etc",         "> /boot",
        ">> /boot",         "> /var",          ">> /var",
    };
    for (const char* pattern : kWritePatterns) {
        if (cmd.find(pattern) != std::string::npos) {
            hit = pattern;
            return false;
        }
    }
    return true;
}

namespace {

constexpr size_t kMaxOutputBytes = 64 * 1024;
constexpr int kPollIntervalMs = 10;
constexpr int kTermGraceMs = 500;

bool SetNonBlocking(int fd) {
    const int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

} // namespace

ExecOutcome RunCheckCommand(const std::string& cmd, int timeout_sec) {
    ExecOutcome outcome;
    outcome.exit_code = -1;

    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) {
        outcome.launched = false;
        outcome.output = std::string("pipe 创建失败: ") + std::strerror(errno);
        return outcome;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        outcome.launched = false;
        outcome.output = std::string("fork 失败: ") + std::strerror(errno);
        return outcome;
    }

    if (pid == 0) {
        // 子进程：stdout/stderr 合并进管道，bash 专属语法（$((8#x))）需要 bash
        close(pipe_fds[0]);
        dup2(pipe_fds[1], STDOUT_FILENO);
        dup2(pipe_fds[1], STDERR_FILENO);
        close(pipe_fds[1]);
        execl("/bin/bash", "bash", "-c", cmd.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }

    close(pipe_fds[1]);
    SetNonBlocking(pipe_fds[0]);
    outcome.launched = true;

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
    char buf[4096];
    int status = 0;
    bool reaped = false;
    bool eof = false;

    while (true) {
        // 尽量读空管道（直到 EAGAIN 或 EOF）
        while (!eof) {
            const ssize_t n = read(pipe_fds[0], buf, sizeof(buf));
            if (n > 0) {
                const size_t remaining =
                    outcome.output.size() < kMaxOutputBytes
                        ? kMaxOutputBytes - outcome.output.size()
                        : 0;
                outcome.output.append(buf, static_cast<size_t>(n) < remaining
                                               ? static_cast<size_t>(n)
                                               : remaining);
            } else if (n == 0) {
                eof = true;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                eof = true;
            } else if (errno == EINTR) {
                continue;
            } else {
                break;
            }
        }

        if (waitpid(pid, &status, WNOHANG) == pid) {
            reaped = true;
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            outcome.timed_out = true;
            kill(pid, SIGTERM);
            const auto kill_at = std::chrono::steady_clock::now() +
                                 std::chrono::milliseconds(kTermGraceMs);
            while (std::chrono::steady_clock::now() < kill_at) {
                if (waitpid(pid, &status, WNOHANG) == pid) {
                    reaped = true;
                    break;
                }
                usleep(kPollIntervalMs * 1000);
            }
            if (!reaped) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                reaped = true;
            }
            break;
        }
        if (eof) {
            // 输出已读完但子进程尚未退出：继续轮询直至退出或超时
            usleep(kPollIntervalMs * 1000);
        } else {
            usleep(kPollIntervalMs * 1000);
        }
    }

    // 收尾：把子进程退出后管道里剩余的数据读掉
    if (reaped) {
        for (;;) {
            const ssize_t n = read(pipe_fds[0], buf, sizeof(buf));
            if (n > 0) {
                const size_t remaining =
                    outcome.output.size() < kMaxOutputBytes
                        ? kMaxOutputBytes - outcome.output.size()
                        : 0;
                outcome.output.append(buf, static_cast<size_t>(n) < remaining
                                               ? static_cast<size_t>(n)
                                               : remaining);
            } else {
                break;
            }
        }
    }
    close(pipe_fds[0]);

    if (reaped && !outcome.timed_out) {
        if (WIFEXITED(status)) {
            outcome.exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            outcome.exit_code = 128 + WTERMSIG(status);
        }
    }
    return outcome;
}

} // namespace cis
