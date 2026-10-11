#pragma once

#include <string>

#include "cis_judge.hpp"

namespace cis {

// 只读守卫：命中潜在写操作子串时填 hit 并返回 false。
bool CommandIsReadOnly(const std::string& cmd, std::string& hit);

// 用 /bin/bash -c 执行命令，stdout/stderr 合并，超时（秒）后 SIGTERM 再 SIGKILL。
// fork/exec 失败置 launched=false 并在 output 写原因；output 上限 64KB。
ExecOutcome RunCheckCommand(const std::string& cmd, int timeout_sec = 5);

} // namespace cis
