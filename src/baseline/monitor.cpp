#include "monitor.hpp"
#include "monitor_internal.hpp"
#include "instance_lock.hpp"
#include "event_bus.hpp"
#include "event_store.hpp"
#include "bpf/stats_slots.h"

#include <bpf/bpf.h>

#include <csignal>
#include <cstdio>
#include <fstream>
#include <pwd.h>
#include <sstream>
#include <string>
#include <sys/utsname.h>
#include <unistd.h>

#include <spdlog/spdlog.h>

volatile bool running = true;

// ── 内核版本检测 ────────────────────────────────────────────────

KernelVersion get_kernel_version() {
    static KernelVersion cached = {0, 0};
    static bool initialized = false;
    if (initialized) return cached;

    struct utsname uts;
    if (uname(&uts) == 0) {
        sscanf(uts.release, "%u.%u", &cached.major, &cached.minor);
    }
    initialized = true;
    return cached;
}

bool kernel_at_least(unsigned int major, unsigned int minor) {
    auto kv = get_kernel_version();
    return kv.major > major || (kv.major == major && kv.minor >= minor);
}

void signal_handler(int sig) {
    running = false;
    if (sig == SIGTERM) {
        spdlog::info("[service_stop] received SIGTERM, shutting down gracefully");
    }
}

std::string ResolveUserInfoByPid(int pid, std::string& uid) {
    uid.clear();
    std::string user_name;

    if (pid <= 0) {
        return user_name;
    }

    // /proc/<pid>/status 读取与进程退出存在竞态：libstdc++ 的
    // basic_filebuf::underflow 遇 ESRCH 会直接抛 ios_failure，
    // 必须兜底，否则异常穿透导致 monitor 进程 terminate
    try {
        const std::string proc_status = "/proc/" + std::to_string(pid) + "/status";
        std::ifstream in(proc_status);
        if (!in.is_open()) {
            return user_name;
        }

        std::string line;
        while (std::getline(in, line)) {
            if (line.rfind("Uid:", 0) == 0) {
                std::istringstream iss(line);
                std::string key;
                iss >> key;
                int raw_uid = 0;
                iss >> raw_uid;
                if (raw_uid > 0) {
                    uid = std::to_string(raw_uid);
                    struct passwd* pw = getpwuid(static_cast<uid_t>(raw_uid));
                    if (pw != nullptr) {
                        user_name = pw->pw_name;
                    }
                }
                break;
            }
        }
    } catch (const std::ios_base::failure&) {
        // 进程在打开 /proc/<pid>/status 后退出：按未知用户处理
    }

    return user_name;
}

// ── 用户态计数器 → pinned user_stats map（stats --drop 读取）─────────
// 槽位定义见 bpf/stats_slots.h；bus/store 为空时对应槽写 0。
void sync_user_stats(int fd, const EventBus* bus, const EventStore* store,
                            const MonitorContext* mctx) {
    if (fd < 0)
        return;
    __u64 vals[USER_STATS_SLOTS] = {};
    if (bus) {
        for (int p = 0; p < 4; p++) {
            vals[USTAT_BUS_DROP_HI_P0 + p] = bus->drop_count(true, p);
            vals[USTAT_BUS_DROP_LO_P0 + p] = bus->drop_count(false, p);
        }
        vals[USTAT_BUS_PUSHED]   = bus->pushed_count();
        vals[USTAT_BUS_HI_DEPTH] = bus->hi_depth();
        vals[USTAT_BUS_LO_DEPTH] = bus->lo_depth();
    }
    if (mctx)
        vals[USTAT_BATCH_OVERFLOW] = mctx->dropped_count;
    if (store) {
        vals[USTAT_STORE_FAILED] = store->failed_count();
        vals[USTAT_STORE_STORED] = store->stored_count();
    }
    for (__u32 i = 0; i < USER_STATS_SLOTS; i++)
        bpf_map_update_elem(fd, &i, &vals[i], BPF_ANY);
}

// ── 入口函数：根据内核版本分派到不同路径 ────────────────────────
int do_monitor(const Config& config, AlertManager &alert_mgr,
               const std::string& config_path,
               const std::string& baseline_db_path, bool skip_boot_check,
               const std::string& lock_path) {

    // ── 单实例锁（W7 D1 / G16）：探针加载、ring buffer 创建之前获取 ──
    // flock 方案：锁由进程级 fd 持有，正常退出与 kill -9 均由内核自动释放，
    // 无 stale pidfile 问题。双开会同时消费 ring buffer 并写同一告警库（G16 串扰）。
    // lock_path 非空时覆盖默认锁路径（云上双实例并存，各持独立锁文件）。
    static const char* kMonitorLockPath = "/var/run/diting-monitor.lock";
    const std::string lock_path_eff = lock_path.empty() ? kMonitorLockPath : lock_path;
    {
        int holder_pid = -1;
        std::string lock_err;
        if (!common::AcquireInstanceLock(lock_path_eff, holder_pid, lock_err)) {
            if (holder_pid > 0) {
                spdlog::error("[instance_lock] 已有 monitor 实例运行（pid {}），拒绝启动；锁文件 {}",
                              holder_pid, lock_path_eff);
            } else {
                spdlog::error("[instance_lock] 获取单实例锁失败: {}（锁文件 {}）",
                              lock_err.empty() ? "锁已被持有" : lock_err, lock_path_eff);
            }
            return 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    // SIGHUP 热加载（M0-2）：handler 只置标志，各路径主循环每轮检查后原子替换快照；
    // 此处注册覆盖 main.cpp 的旧式 g_reload handler（进程不重启，pid 不变）
    signal(SIGHUP, monitor_sighup_handler);

    // ── DSL 规则引擎启动加载（W4）；W7 D1 起 fail-fast ─────────────
    // 策略：任一规则文件加载/编译失败、或 enabled 但加载 0 条规则，均拒绝启动。
    // 根因修复：W6 D3 起 rules/cis 定义文件被当规则解析失败，旧代码静默降级为
    // 空引擎继续运行，DSL 告警空窗 2 天无任何报错——"加载 0 条规则还正常跑"
    // 这条路径必须不存在。探针加载前完成校验，失败无清理负担。
    // （热加载路径语义不同：加载失败保留旧快照继续运行，见 reload_monitor_config。）
    if (config.rule_engine.enabled) {
        auto engine = build_rule_engine(config.rule_engine);
        if (engine == nullptr) {
            spdlog::error("[rule_engine] 规则加载失败，拒绝启动"
                          "（修复规则文件，或置 rule_engine.enabled: false 后重启）");
            return 1;
        }
        {
            std::unique_lock<std::shared_mutex> lk(g_file_rules_mtx);
            g_rule_engine = std::move(engine);
        }
        spdlog::info("[rule_engine] loaded {} DSL rules from {}",
                     rule_engine_snapshot()->rule_count(), config.rule_engine.rules_dir);
    } else {
        spdlog::info("[rule_engine] disabled by config");
    }

    auto kv = get_kernel_version();
    spdlog::info("[kernel_detect] detected kernel {}.{}", kv.major, kv.minor);

    if (kv.major > 5 || (kv.major == 5 && kv.minor >= 8)) {
        // 5.8+: BPF LSM + ring buffer（完整功能）
        return do_monitor_ringbuf(config, alert_mgr, config_path, baseline_db_path, skip_boot_check);
    } else if (kv.major == 5 && kv.minor >= 7) {
        // 5.7: BPF LSM + perf event buffer（支持 block）
        return do_monitor_perf(config, alert_mgr, config_path, baseline_db_path, skip_boot_check);
    } else if (kv.major == 5 && kv.minor >= 4) {
        // 5.4~5.6: kprobe + perf event buffer（仅告警）
        return do_monitor_kprobe(config, alert_mgr, config_path, baseline_db_path, skip_boot_check);
    } else {
        spdlog::error("[kernel_unsupported] kernel {}.{} not supported, minimum is 5.4",
                     kv.major, kv.minor);
        return 1;
    }
}
