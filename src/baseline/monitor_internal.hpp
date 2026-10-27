#pragma once

// monitor 模块内部共享声明（monitor.cpp / monitor_rules.cpp / monitor_file.cpp /
// monitor_dsl.cpp / monitor_telemetry.cpp / monitor_paths.cpp 拆分共用）。
// 仅供 src/baseline/monitor*.cpp 使用，不对外暴露。

#include "baseline.hpp"
#include "config.hpp"
#include "alert_manager.hpp"
#include "baseline_db.hpp"
#include "event_record.hpp"
#include "rule_engine.hpp"
#include "rule_loader.hpp"
#include "watermark_backpressure.hpp"
#include "whitelist.hpp"
#include "bpf/event.h"

#include <csignal>
#include <cstddef>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

class EventBus;
class EventStore;
class ProcessTree;
class Enricher;
struct proc_event;
struct net_event;
struct priv_event;

// ── 全局退出标志与信号处理 ──────────────────────────────────────
extern volatile bool running;
void signal_handler(int sig);

// ── 内核版本检测 ────────────────────────────────────────────────
struct KernelVersion { unsigned int major, minor; };
KernelVersion get_kernel_version();
bool kernel_at_least(unsigned int major, unsigned int minor);

std::string ResolveUserInfoByPid(int pid, std::string& uid);

// ── 规则表快照与热加载（M0-2）────────────────────────────────────
// FileRuleTable 为整代不可变快照：SIGHUP 热加载在写锁内整体替换；
// 事件处理（消费线程 / perf 主循环）持读锁访问，锁内 Rule 引用恒有效。
// R13：inode_to_rules 一对多——同一文件配置多条规则时各自独立告警
//（原先 unordered_map<ino, Rule> 后写覆盖先写，仅最后一条生效）。
struct FileRuleTable {
    std::unordered_map<unsigned long, std::vector<Rule>> inode_to_rules;
    std::unordered_map<unsigned long, std::string> inode_to_path;
    std::unordered_map<unsigned long, std::vector<std::string>> inode_to_hashes;

    static std::shared_ptr<FileRuleTable> Build(const Config& config) {
        auto t = std::make_shared<FileRuleTable>();
        for (const auto& rule : config.rules) {
            if (!rule.has_monitor)
                continue;
            if (rule.monitor_path.empty())
                continue;
            if (rule.ino == 0)
                continue;
            t->inode_to_rules[rule.ino].push_back(rule);
            t->inode_to_path[rule.ino] = rule.monitor_path;
            if (!rule.check_hash.empty())
                t->inode_to_hashes[rule.ino].push_back(rule.check_hash);
        }
        return t;
    }
};

extern std::shared_ptr<FileRuleTable> g_file_rules;
// 白名单不可变快照，与规则表同锁替换：读侧持锁取 const 引用，匹配无锁读表
extern std::shared_ptr<const WhitelistTable> g_whitelist_table;
// DSL 规则引擎快照（W4）：与 FileRuleTable 同锁整代替换；空引擎求值一次分支即返回
extern std::shared_ptr<const detect::RuleEngine> g_rule_engine;
extern std::shared_mutex g_file_rules_mtx;
extern WhitelistMatcher g_whitelist_matcher;

// ── DSL 文件规则 inode 登记（W7 D1 缺口一修复）────────────────────
struct DslInoReg { int refs = 0; bool map_owner = false; };
extern std::unordered_map<unsigned long, DslInoReg> g_dsl_ino_refs;
// ino → 全路径（file_event_path 解析 DSL 专属 inode 的全路径；内核事件只带 basename）
extern std::unordered_map<unsigned long, std::string> g_dsl_ino_path;
// build_rule_engine 最近一次成功加载提取的登记候选（启动/热加载共用交接）
extern std::vector<detect::FilePathRef> g_dsl_pending_refs;
// monitor_actions map fd（common_monitor_init 赋值；SIGHUP 热加载反登记用）
extern int g_fd_actions;

// 基线实时监控映射：inode -> CheckEntry（仅当 --db 模式下非空；启动时构建，热加载不变更）
extern std::unordered_map<unsigned long, CheckEntry> g_inode_to_baseline;

// 消费线程取引擎快照（shared_ptr 拷贝，锁内一次原子增减）
std::shared_ptr<const detect::RuleEngine> rule_engine_snapshot();

// 启动/热加载共用：严格加载 rules_dir 并编译引擎；失败返回 nullptr。
// 调用方语义：启动路径 fail-fast 拒绝启动；热加载路径保留旧快照。
std::shared_ptr<const detect::RuleEngine> build_rule_engine(const RuleEngineConfig& cfg);

// DSL 文件路径登记/反登记同步（启动与热加载共用；W7 D1 任务 3/4）
void dsl_sync_registrations(int fd_actions, const std::vector<detect::FilePathRef> &refs);

// ── SIGHUP 热加载 ─────────────────────────────────────────────
extern volatile sig_atomic_t g_sighup_pending;
void monitor_sighup_handler(int);
void reload_monitor_config(const std::string& config_path, AlertManager& alert_mgr);
void log_suppressed_stats(const AlertManager* alert_mgr = nullptr);

// ── 监控上下文：聚合 AlertManager + 水位背压控制器 + 事件批量缓冲 ──
static constexpr size_t kMaxBatchSize = 1024;

struct MonitorContext {
    AlertManager*            alert_mgr    = nullptr;
    WatermarkBackpressure*   backpressure = nullptr;
    std::vector<struct event> event_batch;
    size_t                   dropped_count = 0;
    int                      user_stats_fd = -1;   // pinned user_stats map（批溢出计数暴露）
};

// 消费线程运行时上下文（聚合总线 / 进程树 / 富化器 / 落库 / 文件处理）
struct TelemetryRuntime {
    EventBus*              bus       = nullptr;
    MonitorContext*        mctx      = nullptr;   // 文件事件路由回 process_event_core
    ProcessTree*           tree      = nullptr;
    Enricher*              enricher  = nullptr;
    EventStore*            store     = nullptr;   // store 关闭时为 nullptr
    bool                   store_on  = false;
    bool                   proc_tree_on = false;  // proc_watch 启动成功为 true（文件事件富化）
    volatile bool*         running   = nullptr;   // 全局退出标志
    AlertManager*          alert_mgr = nullptr;   // retention（已移至消费线程）
    int                    user_stats_fd = -1;    // pinned user_stats map（计数器暴露）
};

// ── 用户态计数器 → pinned user_stats map（stats --drop 读取）─────────
void sync_user_stats(int fd, const EventBus* bus, const EventStore* store,
                     const MonitorContext* mctx);

// ── 核心事件处理逻辑 ────────────────────────────────────────────────
void process_event_core(struct event* e, MonitorContext* mctx,
                        const FileActorContext* actor);

// ── 文件事件进程上下文组装（仅消费线程调用）────────────────────────
FileActorContext build_file_actor(const struct event& e, TelemetryRuntime* rt);
std::string cached_user_name(unsigned int uid);

// ── 文件事件落库渲染（M0-1：CAT_FILE 对齐标准路径）────────────────
const char* file_event_kind(const struct event& e);
std::string file_event_path(const struct event& e);
void render_file_payload(const struct event& e, struct EventRecord& rec,
                         const FileActorContext* actor, Enricher* enr,
                         std::string& out);

// ── DSL 规则引擎接入（W4 D4）：仅消费线程调用，引擎快照只读 ─────────
void eval_rules_on_file_event(const struct event& fe, const FileActorContext* actor,
                              TelemetryRuntime* rt);
void eval_rules_on_exec_event(const struct proc_event& pe, TelemetryRuntime* rt);
void eval_rules_on_net_event(const struct net_event& ne, const EventRecord& rec,
                             const nlohmann::json& j, TelemetryRuntime* rt);
void eval_rules_on_priv_event(const struct priv_event& pe, const EventRecord& rec,
                              const nlohmann::json& j, TelemetryRuntime* rt);

// 消费线程主循环（monitor_telemetry.cpp）
void telemetry_consumer_main(TelemetryRuntime* rt);

// ── 三条内核版本路径（monitor_paths.cpp）──────────────────────────
int do_monitor_ringbuf(const Config& config, AlertManager &alert_mgr,
                       const std::string& config_path,
                       const std::string& baseline_db_path, bool skip_boot_check);
int do_monitor_perf(const Config& config, AlertManager &alert_mgr,
                    const std::string& config_path,
                    const std::string& baseline_db_path, bool skip_boot_check);
int do_monitor_kprobe(const Config& config, AlertManager &alert_mgr,
                      const std::string& config_path,
                      const std::string& baseline_db_path, bool skip_boot_check);
