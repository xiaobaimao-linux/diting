// 单元测试：进程树（M0-1：ProcNode 身份字段 / (pid,start_time) 版本查找 /
// tombstone 可查性）。编译目标见 tests/Makefile（test_process_tree）。
//
// 说明：fake pid（424242x）在系统中不存在，apply() 内对 /proc 的尽力读取
// 全部失败，正好隔离出“纯事件字段”路径；涉及真实 /proc 解析的断言改用
// 测试进程自身 pid。

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

#include "container.hpp"
#include "process_tree.hpp"

static proc_event make_event(unsigned char kind, unsigned int pid, unsigned int ppid) {
    proc_event pe{};
    pe.kind = kind;
    pe.pid = pid;
    pe.ppid = ppid;
    return pe;
}

// 测试用全量容器 ID（64 hex），短 ID 为前 12 位
static const char* kTestFullId =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char* kTestShortId = "0123456789ab";

// ====== CG-001: cgroup 叶子目录名解析容器短 ID ========================
static void test_parse_cgroup_name() {
    // docker systemd 驱动：docker-<64hex>.scope
    assert(parse_container_id_from_cgroup_name(
               std::string("docker-") + kTestFullId + ".scope") == kTestShortId);
    // docker cgroupfs 驱动：裸 64 hex
    assert(parse_container_id_from_cgroup_name(kTestFullId) == kTestShortId);
    // containerd：cri-containerd-<64hex>(.scope)
    assert(parse_container_id_from_cgroup_name(
               std::string("cri-containerd-") + kTestFullId + ".scope") == kTestShortId);
    assert(parse_container_id_from_cgroup_name(
               std::string("cri-containerd-") + kTestFullId) == kTestShortId);
    // crio：crio-<64hex>(.scope)
    assert(parse_container_id_from_cgroup_name(
               std::string("crio-") + kTestFullId + ".scope") == kTestShortId);
    assert(parse_container_id_from_cgroup_name(
               std::string("crio-") + kTestFullId) == kTestShortId);
    // 截断容忍：64B 事件字段截断的 systemd scope 名（docker- + 56 hex）仍可解析
    assert(parse_container_id_from_cgroup_name(
               (std::string("docker-") + kTestFullId + ".scope").substr(0, 63)) == kTestShortId);
    // 非容器名 / 过短 hex / 空串 / 非法后缀 / 含非 hex 字符：均返回空
    assert(parse_container_id_from_cgroup_name("system.slice").empty());
    assert(parse_container_id_from_cgroup_name("user.slice").empty());
    assert(parse_container_id_from_cgroup_name("docker-0123456789a.scope").empty());
    assert(parse_container_id_from_cgroup_name("").empty());
    assert(parse_container_id_from_cgroup_name(
               std::string("docker-") + kTestFullId + ".scopex").empty());
    assert(parse_container_id_from_cgroup_name("0123456789ab").size() == 12);
    assert(parse_container_id_from_cgroup_name("0123abcdefg8ab").empty());
    printf("  [PASS] CG-001: cgroup 名解析 docker scope/cgroupfs/containerd/crio/非容器\n");
}

// ====== PT-001: bootstrap 存储 uid/gid（与 /proc 一致）+ 容器字段一致 ======
static void test_bootstrap_identity() {
    ProcessTree tree;
    tree.bootstrap();

    // 自身进程必有节点；uid 与 getuid() 一致，start_time 非 0
    const ProcNode* self = tree.find(static_cast<unsigned int>(getpid()));
    assert(self != nullptr);
    assert(self->uid == static_cast<unsigned int>(getuid()));
    assert(self->start_time != 0);
    // comm 为二进制名截断到 15 字符（TASK_COMM_LEN-1）
    std::string expected_comm = "test_process_tree";
    expected_comm.resize(15);
    assert(self->comm_str() == expected_comm);

    // 容器短 ID 与 /proc 解析一致；非空时必须是 12 位
    assert(self->container_id_str() == container_id_of(getpid()));
    if (!self->container_id_str().empty())
        assert(self->container_id_str().size() == 12);

    // 1 号进程（init）必有节点
    assert(tree.find(1) != nullptr);
    printf("  [PASS] PT-001: bootstrap 存储 uid/gid + 容器字段与 /proc 一致\n");
}

// ====== PT-002: fork 事件存 uid/gid；事件 cgroup_name 非容器名时容器留空 ====
static void test_fork_stores_uid_gid() {
    ProcessTree tree;
    proc_event pe = make_event(PROC_KIND_FORK, 4242420, 1);
    pe.uid = 1000;
    pe.gid = 1001;
    strcpy(pe.comm, "forktest");
    strcpy(pe.cgroup_name, "system.slice");  // 非容器名：解析为空，fake pid 回落 /proc 亦失败
    tree.apply(pe);

    const ProcNode* node = tree.find(pe.pid);
    assert(node != nullptr);
    assert(node->uid == 1000 && node->gid == 1001);
    assert(node->ppid == 1);
    assert(node->comm_str() == "forktest");
    assert(node->container_id_str().empty());
    printf("  [PASS] PT-002: fork 存 uid/gid、非容器 cgroup 名时 container_id 留空\n");
}

// ====== PT-003: exec 更新 uid/gid + container_id（已有节点 + 就地补建）====
static void test_exec_fills_identity() {
    ProcessTree tree;

    // 就地补建：树中无此 pid（fake pid，/proc 读取失败走事件值）
    proc_event pe = make_event(PROC_KIND_EXEC, 4242421, 4242420);
    pe.uid = 1002;
    pe.gid = 1003;
    pe.start_time = 123456789ULL;
    strcpy(pe.comm, "exectest");
    tree.apply(pe);

    const ProcNode* node = tree.find(pe.pid);
    assert(node != nullptr);
    assert(node->uid == 1002 && node->gid == 1003);
    assert(node->start_time == 123456789ULL);
    assert(node->container_id_str().empty());  // fake pid 无 /proc，容器留空

    // 已有节点（测试进程自身）：container_id/exe 与 /proc 解析一致
    proc_event me = make_event(PROC_KIND_EXEC,
                               static_cast<unsigned int>(getpid()),
                               static_cast<unsigned int>(getppid()));
    me.uid = 4242;
    me.gid = 4243;
    strcpy(me.comm, "pt_exec_self");
    tree.apply(me);

    const ProcNode* self = tree.find(static_cast<unsigned int>(getpid()));
    assert(self != nullptr);
    assert(self->uid == 4242 && self->gid == 4243);
    assert(self->comm_str() == "pt_exec_self");
    assert(self->container_id_str() == container_id_of(getpid()));
    assert(self->exe_str() == exe_path_of(getpid()));
    printf("  [PASS] PT-003: exec 更新 uid/gid + container_id（就地补建 + 已有节点）\n");
}

// ====== PT-004: find(pid, start_time) 版本匹配（pid 复用防护）============
static void test_find_by_start_time() {
    ProcessTree tree;
    proc_event pe = make_event(PROC_KIND_EXEC, 4242422, 1);
    pe.uid = 7;
    pe.gid = 8;
    pe.start_time = 111222333ULL;
    tree.apply(pe);

    // start_time 匹配 / 为 0 退化 / 不匹配（pid 复用）/ pid 不存在
    assert(tree.find(pe.pid, 111222333ULL) != nullptr);
    assert(tree.find(pe.pid, 0) != nullptr);
    assert(tree.find(pe.pid, 999888777ULL) == nullptr);
    assert(tree.find(7777777, 111222333ULL) == nullptr);
    // 节点身份字段经重载查找仍可取
    const ProcNode* node = tree.find(pe.pid, 111222333ULL);
    assert(node->uid == 7 && node->gid == 8);
    printf("  [PASS] PT-004: find(pid,start_time) 匹配/退化/复用返回空\n");
}

// ====== PT-005: tombstone 节点仍可查（含身份字段），sweep 不误删 ========
static void test_tombstone_findable() {
    ProcessTree tree;
    proc_event fork = make_event(PROC_KIND_FORK, 4242423, 1);
    fork.uid = 9;
    fork.gid = 10;
    tree.apply(fork);

    proc_event exit_e = make_event(PROC_KIND_EXIT, 4242423, 1);
    exit_e.start_time = 555ULL;
    tree.apply(exit_e);

    const ProcNode* node = tree.find(4242423);
    assert(node != nullptr);
    assert(node->exited);
    assert(node->uid == 9 && node->gid == 10);  // tombstone 保留 fork 时身份
    // 未过 60s 窗口，sweep 不得清除
    tree.sweep_tombstones();
    assert(tree.find(4242423) != nullptr);
    assert(tree.tombstone_count() == 1);
    printf("  [PASS] PT-005: tombstone 可查且保留身份字段、sweep 不误删\n");
}

// ====== PT-006: 事件自带 cgroup_name 优先（fake pid 无 /proc，纯事件路径）==
static void test_event_cgroup_name_priority() {
    ProcessTree tree;

    // fork：事件 cgroup_name 携带 docker scope 名，直接落节点容器短 ID
    // （pid 不存在于 /proc，证明不依赖事后 /proc 读取——case-06 竞态根治路径）
    proc_event fork_e = make_event(PROC_KIND_FORK, 4242424, 1);
    strcpy(fork_e.comm, "sh");
    snprintf(fork_e.cgroup_name, sizeof(fork_e.cgroup_name), "docker-%s.scope", kTestFullId);
    tree.apply(fork_e);
    const ProcNode* node = tree.find(4242424);
    assert(node != nullptr);
    assert(node->container_id_str() == kTestShortId);

    // exec：同样优先事件 cgroup_name（就地补建分支）
    proc_event exec_e = make_event(PROC_KIND_EXEC, 4242425, 4242424);
    exec_e.start_time = 987654321ULL;
    strcpy(exec_e.comm, "sh");
    snprintf(exec_e.cgroup_name, sizeof(exec_e.cgroup_name), "crio-%s.scope", kTestFullId);
    tree.apply(exec_e);
    const ProcNode* exec_node = tree.find(4242425);
    assert(exec_node != nullptr);
    assert(exec_node->container_id_str() == kTestShortId);

    // exec 已有节点：cgroup_name 为空串时回落 /proc（fake pid 失败 → 清空容器归属）
    exec_e.cgroup_name[0] = '\0';
    tree.apply(exec_e);
    assert(tree.find(4242425)->container_id_str().empty());
    printf("  [PASS] PT-006: 事件 cgroup_name 优先、空串回落 /proc\n");
}

int main() {
    printf("=== test_process_tree ===\n");
    test_parse_cgroup_name();
    test_bootstrap_identity();
    test_fork_stores_uid_gid();
    test_exec_fills_identity();
    test_find_by_start_time();
    test_tombstone_findable();
    test_event_cgroup_name_priority();
    printf("=== all process_tree tests passed ===\n");
    return 0;
}
