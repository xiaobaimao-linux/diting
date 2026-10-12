#pragma once

#include <string>

namespace common {

// 单实例锁（flock 方案，W7 D1 / G16）。
// 成功返回 true：锁由进程级持有的 fd 保持，正常退出与 kill -9 均由内核自动释放；
// 并把本进程 pid 写入锁文件（供冲突方报错引用）。
// 冲突返回 false：holder_pid 尽力从锁文件读出（读不到为 -1），err 为系统错误描述。
// 同一进程重复调用幂等（已持有直接返回 true）。
bool AcquireInstanceLock(const std::string &lock_path, int &holder_pid, std::string &err);

} // namespace common
