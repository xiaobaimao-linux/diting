#pragma once

#include <string>

// 从 /proc/<pid>/cgroup 解析容器 ID：匹配 docker-/cri-containerd-/crio-/docker/ 前缀，
// 提取 64 位十六进制 ID 并截断为 12 位短 ID。
// 宿主机进程、短寿进程 /proc 已消失、解析失败均返回空串（调用方应省略 container 字段）。
std::string container_id_of(int pid);

// 从 cgroup 叶子目录名（内核事件自带的 cgroup_name）解析容器短 ID：
// 支持 docker-/cri-containerd-/crio- 前缀（systemd 驱动带 .scope 后缀）及
// 裸 hex 名（docker cgroupfs 驱动）；hex 段 ≥12 位即接收（事件字段 64B 截断
// 容忍），不匹配返回空串。
std::string parse_container_id_from_cgroup_name(const std::string& name);

// /proc/<pid>/exe readlink 解析进程真实可执行路径。
// 短寿进程 /proc 已回收、内核线程（无 exe）等失败场景返回空串（调用方尽力处理）。
std::string exe_path_of(int pid);
