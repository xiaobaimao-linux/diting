#include "monitor_internal.hpp"
#include "monitor_baseline.hpp"
#include "monitor_network.hpp"
#include "monitor_process.hpp"
#include "monitor_privilege.hpp"
#include "baseline_db.hpp"
#include "event_bus.hpp"
#include "event_store.hpp"
#include "process_tree.hpp"
#include "enricher.hpp"
#include "utils.hpp"
#include "commonfun.hpp"
#include "container.hpp"
#include "net_event.h"
#include "priv_event.h"
#include "proc_event.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_version.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <thread>
#include <pwd.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

using json = nlohmann::json;

// 包含生成的skeleton头文件（经 -I. 从仓库根目录引用 bpf/）
#include "bpf/lsm_file.skel.h"        // 5.8+ ring buffer
#include "bpf/lsm_file_perf.skel.h"   // 5.7 perf buffer
#include "bpf/lsm_kprobe.skel.h"      // 5.4 kprobe

// pin 辅助：先 unlink 陈旧 pin（上次异常退出残留）再 pin，失败仅告警
static void pin_map_best_effort(struct bpf_map* map, const char* path) {
    unlink(path);
    if (int err = bpf_map__pin(map, path))
        spdlog::warn("[bpf_map_pin] failed to pin {}: {}", path, strerror(-err));
}

// ── 事件回调（ring buffer 路径）：struct event 归一化为 EventRecord 入事件总线 ──
// 只做归一化 + try_push（禁 malloc / 阻塞 / /proc IO），由消费线程路由回
// 原文件处理函数 process_event_core（行为零变化）。
static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)data_sz;

    auto* bus = static_cast<EventBus*>(ctx);
    if (!bus)
        return 0;
    auto* e = static_cast<struct event *>(data);

    EventRecord rec{};   // 定长 POD，零初始化
    rec.ts_ns         = now_monotonic_ns();  // 文件事件无内核 ts，以入队时间计
    rec.enqueue_ts_ns = rec.ts_ns;
    rec.pid           = e->pid;
    memcpy(rec.comm, e->comm, sizeof(rec.comm));
    rec.category = CAT_FILE;
    rec.priority = PRIO_FILE;
    rec.action   = e->event_type;
    static_assert(sizeof(*e) <= sizeof(rec.payload_raw), "struct event 超出 payload_raw 容量");
    memcpy(rec.payload_raw, e, sizeof(*e));  // struct event 原始字节，供消费线程还原

    bus->try_push(rec);
    return 0;
}

// perf event buffer 回调签名（5.7 / 5.4 路径复用）
static void perf_event_cb(void *ctx, int cpu, void *data, __u32 size) {
    (void)cpu;
    auto* mctx = static_cast<MonitorContext*>(ctx);
    auto* e    = static_cast<struct event *>(data);

    if (size < sizeof(struct event))
        return;

    if (mctx->event_batch.size() < kMaxBatchSize) {
        mctx->event_batch.push_back(*e);
    } else {
        mctx->dropped_count++;
    }
}

// perf_buffer__new 兼容封装：libbpf 0.6 起为回调直传六参形式，0.5
// （Ubuntu 22.04 自带）只有 opts 三参形式；libbpf_version.h 自 0.6 引入。
static struct perf_buffer* new_perf_buffer_compat(int map_fd, size_t page_cnt,
                                                  perf_buffer_sample_fn sample_cb,
                                                  void* ctx) {
#if defined(LIBBPF_MAJOR_VERSION) && \
    (LIBBPF_MAJOR_VERSION > 0 || LIBBPF_MINOR_VERSION >= 6)
    return perf_buffer__new(map_fd, page_cnt, sample_cb, nullptr, ctx, nullptr);
#else
    struct perf_buffer_opts opts = {};
    opts.sample_cb = sample_cb;
    opts.ctx = ctx;
    return perf_buffer__new(map_fd, page_cnt, &opts);
#endif
}

// ── perf 降级路径（5.7/5.4）操作者上下文：无进程树/消费线程，按事件 uid/gid +
// /proc 尽力组装（exe/container 依赖 /proc/<pid>，进程已退出则留空、字段省略），
// 使降级路径告警同样携带操作者上下文；不报错不崩溃。
static FileActorContext build_file_actor_fallback(const struct event& e) {
    FileActorContext actor;
    actor.uid = e.uid;
    actor.gid = e.gid;
    if (struct passwd* pw = getpwuid(static_cast<uid_t>(e.uid)))
        actor.user_name = pw->pw_name;
    actor.exe = exe_path_of(static_cast<int>(e.pid));
    actor.container_id = container_id_of(static_cast<int>(e.pid));
    return actor;
}

// ── 批量处理：遍历缓冲区中的所有事件，逐条调用核心处理逻辑 ────────
// perf buffer 路径（5.7 / 5.4）无进程树：按事件 uid/gid + /proc 尽力组装
// 操作者上下文（build_file_actor_fallback），告警同样富化。
static void FlushEventBatch(MonitorContext* mctx) {
    for (auto& e : mctx->event_batch) {
        FileActorContext actor = build_file_actor_fallback(e);
        process_event_core(&e, mctx, &actor);
    }
    mctx->event_batch.clear();
}

// ── 降级路径遥测可用性提示（perf / kprobe，内核 < 5.8）────────────
// 遥测事件通道依赖 ring buffer（5.8+），降级路径不初始化遥测；
// 配置开关开着却无任何加载痕迹属静默缺失，此处补一行警告并列出被忽略的开关。
static void warn_telemetry_unavailable(const Config& config) {
    std::vector<const char*> enabled;
    if (config.telemetry.network)   enabled.push_back("network");
    if (config.telemetry.dns)       enabled.push_back("dns");
    if (config.telemetry.privilege) enabled.push_back("privilege");
    if (config.telemetry.store)     enabled.push_back("store");
    if (enabled.empty())
        return;

    std::string names;
    for (size_t i = 0; i < enabled.size(); ++i) {
        if (i > 0) names += ' ';
        names += enabled[i];
    }
    spdlog::warn("[telemetry] kernel <5.8 无 ring buffer，遥测不可用（perf 降级版待开发），已忽略配置: {}",
                 names);
}

// ── 公共初始化：写入规则到 eBPF map + 基线加载 ─────────────────
static int common_monitor_init(int fd_actions,
                               const Config& config,
                               const std::string& baseline_db_path,
                               bool skip_boot_check,
                               AlertManager& alert_mgr,
                               BaselineDB*& baseline_db_out) {
    g_fd_actions = fd_actions; // SIGHUP 热加载 DSL 登记同步用（map fd 进程内不变）
    // 写入 monitor_actions：同 inode 的多条规则合并为一个 monitor_rule_set
    // 一次写入（R13 缺陷修复：原先逐条 BPF_ANY 更新同 key，后写覆盖先写）。
    // 超过 MAX_RULES_PER_INO 时保留 action/severity 最强者并 warn 留痕。
    std::unordered_map<unsigned long, monitor_rule_set> rule_sets;
    for (const auto &rule : config.rules) {
        if (!rule.has_monitor)
            continue;
        if (rule.monitor_path.empty() || rule.ino == 0)
            continue;

        struct monitor_rule value{};
        value.action = (rule.monitor_action == Action::BLOCK) ? ACTION_BLOCK : ACTION_ALERT;
        value.events_mask = 0;
        if (rule.monitor_read)
            value.events_mask |= EVENT_READ;
        if (rule.monitor_write)
            value.events_mask |= EVENT_WRITE;
        if (rule.monitor_delete)
            value.events_mask |= EVENT_MASK_BIT(EVENT_UNLINK);
        if (rule.monitor_chmod)
            value.events_mask |= EVENT_MASK_BIT(EVENT_CHMOD);
        if (rule.monitor_chown)
            value.events_mask |= EVENT_MASK_BIT(EVENT_CHOWN);
        value.severity = rule.severity;

        auto &set = rule_sets[rule.ino];
        if (set.count < MAX_RULES_PER_INO) {
            set.rules[set.count++] = value;
        } else {
            // 已满：仅当新规则严格强于最弱条目时替换之
            int weakest = 0;
            for (int i = 1; i < MAX_RULES_PER_INO; i++) {
                if (set.rules[i].action < set.rules[weakest].action ||
                    (set.rules[i].action == set.rules[weakest].action &&
                     set.rules[i].severity < set.rules[weakest].severity))
                    weakest = i;
            }
            if (value.action > set.rules[weakest].action ||
                (value.action == set.rules[weakest].action &&
                 value.severity > set.rules[weakest].severity)) {
                set.rules[weakest] = value;
            }
            spdlog::warn("[rules] inode {} 规则数超过 {}，已保留最强的 {} 条（rule {} 被合并丢弃）",
                         rule.ino, MAX_RULES_PER_INO, MAX_RULES_PER_INO, rule.id);
        }
    }

    // 安装规则表 + 白名单快照（启动代；SIGHUP 热加载时整代替换）
    {
        std::unique_lock<std::shared_mutex> lk(g_file_rules_mtx);
        g_file_rules = FileRuleTable::Build(config);
        g_whitelist_table = WhitelistTable::Build(config);
    }
    g_whitelist_matcher.ClearCache();

    // ── 基线实时监控初始化（仅当 --db 模式下）────────────────
    baseline_db_out = nullptr;
    if (!baseline_db_path.empty()) {
        try {
            baseline_db_out = new BaselineDB(baseline_db_path);

            g_inode_to_baseline.clear();
            auto entries = baseline_db_out->GetAllBaselineEntries();
            for (auto& e : entries) {
                struct stat st;
                if (lstat(e.file_path.c_str(), &st) == 0 && st.st_ino != 0) {
                    g_inode_to_baseline[st.st_ino] = e;
                }
            }
            spdlog::info("[baseline_monitor] loaded {} baseline entries from {}",
                         g_inode_to_baseline.size(), baseline_db_path);

            int baseline_registered = 0;
            for (const auto& [ino, entry] : g_inode_to_baseline) {
                // 语义保持：YAML 规则已覆盖的 inode 不再注册基线伪规则
                //（原 BPF_NOEXIST + 显式跳过的行为）
                if (rule_sets.find(ino) != rule_sets.end())
                    continue;
                auto &set = rule_sets[ino];
                struct monitor_rule value{};
                value.action = ACTION_ALERT;
                // 基线完整性关注内容读写 + 权限/属主变更（perm_changed 风险类型）
                value.events_mask = EVENT_READ | EVENT_WRITE |
                                    EVENT_MASK_BIT(EVENT_CHMOD) |
                                    EVENT_MASK_BIT(EVENT_CHOWN);
                value.severity = SEVERITY_HIGH;
                set.rules[set.count++] = value;
                ++baseline_registered;
            }
            spdlog::info("[baseline_monitor] registered {} baseline inodes to eBPF map",
                         baseline_registered);

            if (!skip_boot_check) {
                int boot_devs = 0;
                for (const auto& [ino, entry] : g_inode_to_baseline) {
                    std::vector<BaselineDeviation> devs = CompareWithBaseline(entry, entry.file_path);
                    for (const auto& dev : devs) {
                        // boot check 无进程上下文（启动时无事件关联），actor 传 nullptr
                        HandleBaselineDeviation(dev, entry.file_path, "-", 0, alert_mgr,
                                                kBaselineCheckRuleId, nullptr);
                        ++boot_devs;
                    }
                }
                spdlog::info("[baseline_boot_check] completed, {} deviations found", boot_devs);
            } else {
                spdlog::info("[baseline_boot_check] skipped (--skip-boot-baseline-check)");
            }
        } catch (const std::exception& ex) {
            spdlog::error("[baseline_monitor] failed to open baseline DB: {}", ex.what());
            delete baseline_db_out;
            baseline_db_out = nullptr;
            g_inode_to_baseline.clear();
        }
    }

    // 统一下刷：每个 inode 一条 rule_set 记录（含 YAML 规则与基线伪规则）
    int rules_written = 0;
    for (auto &[ino, set] : rule_sets) {
        if (bpf_map_update_elem(fd_actions, &ino, &set, BPF_ANY) == 0)
            ++rules_written;
    }
    spdlog::info("[rules] monitor_actions: {} inodes written", rules_written);

    // DSL 文件规则路径登记（W7 D1）：在 config/基线下刷之后执行，
    // 覆盖判定以 g_file_rules / g_inode_to_baseline 为准
    dsl_sync_registrations(fd_actions, g_dsl_pending_refs);
    return 0;
}

// ── 公共监控循环（perf buffer 路径，5.7 和 5.4 共用）──────────
static int run_perf_buffer_loop(struct perf_buffer *pb,
                                MonitorContext& mctx,
                                AlertManager& alert_mgr,
                                const std::string& config_path) {
    int count = 0;
    const int RETENTION_INTERVAL = 36000;
    const int WL_STATS_INTERVAL = 600;   // 100ms 轮询 × 600 = 60s 抑制计数日志
    const int USTATS_INTERVAL = 10;      // 100ms 轮询 × 10 = 1s 用户态计数器同步

    while (running) {
        count++;
        int err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            spdlog::error("[bpf_program_error] Error polling perf buffer: {}", err);
            break;
        }

        // SIGHUP 热加载：handler 只置标志，此处每轮检查（成功替换快照，失败保留旧配置）
        if (g_sighup_pending) {
            g_sighup_pending = 0;
            reload_monitor_config(config_path, alert_mgr);
        }

        FlushEventBatch(&mctx);

        // 用户态计数器暴露（perf 降级路径无消费线程，此处周期同步批溢出计数）
        if (count % USTATS_INTERVAL == 0)
            sync_user_stats(mctx.user_stats_fd, nullptr, nullptr, &mctx);

        if (count % RETENTION_INTERVAL == 0) {
            int deleted = alert_mgr.RunRetention();
            (void)deleted;
        }
        if (count % WL_STATS_INTERVAL == 0) {
            log_suppressed_stats(&alert_mgr);
        }
    }

    FlushEventBatch(&mctx);
    sync_user_stats(mctx.user_stats_fd, nullptr, nullptr, &mctx);

    if (mctx.dropped_count > 0) {
        spdlog::warn("[batch] {} events dropped (batch overflow, max_batch_size={})",
                     mctx.dropped_count, kMaxBatchSize);
    }
    return 0;
}

// ══════════════════════════════════════════════════════════════════
// 路径 A：内核 5.8+ — BPF LSM + ring buffer
// ══════════════════════════════════════════════════════════════════
int do_monitor_ringbuf(const Config& config, AlertManager &alert_mgr,
                              const std::string& config_path,
                              const std::string& baseline_db_path, bool skip_boot_check) {
    struct lsm_file_bpf *skel;
    int err;

    skel = lsm_file_bpf__open();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open BPF skeleton");
        return 1;
    }

    // 兼容内核 5.8：mmap_file LSM hook 在 5.9 才引入
    if (skel->progs.file_mmap_hook && !kernel_at_least(5, 9)) {
        bpf_program__set_autoload(skel->progs.file_mmap_hook, false);
        auto kv = get_kernel_version();
        spdlog::info("[bpf_compat] mmap_file hook disabled (kernel {}.{}, requires 5.9+)",
                     kv.major, kv.minor);
    }

    err = lsm_file_bpf__load(skel);
    if (err) {
        // 旧内核（实测 5.15）verifier 不支持 LSM hook 原型中的按值 STRUCT 参数
        // （path_chown 的 kuid_t/kgid_t），load 直接 -EINVAL。降级：禁载
        // file_chown_hook（丢失 CHOWN 检测，其余探针不受影响）后重试。
        auto kv = get_kernel_version();
        spdlog::warn("[bpf_compat] skeleton load failed ({}), kernel {}.{}: "
                     "retry without path_chown hook (CHOWN detection degraded)",
                     err, kv.major, kv.minor);
        lsm_file_bpf__destroy(skel);
        skel = lsm_file_bpf__open();
        if (!skel) {
            spdlog::error("[bpf_program_error] Failed to reopen BPF skeleton");
            return 1;
        }
        if (skel->progs.file_mmap_hook && !kernel_at_least(5, 9))
            bpf_program__set_autoload(skel->progs.file_mmap_hook, false);
        bpf_program__set_autoload(skel->progs.file_chown_hook, false);
        err = lsm_file_bpf__load(skel);
        if (err) {
            spdlog::error("[bpf_program_error] Failed to load BPF skeleton: {}", err);
            lsm_file_bpf__destroy(skel);
            return 1;
        }
    }

    err = lsm_file_bpf__attach(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to attach BPF program: {}", err);
        lsm_file_bpf__destroy(skel);
        return 1;
    }
    spdlog::info("[bpf_program_loaded] BPF LSM (ring buffer) attached, kernel 5.8+, {} rules",
                 config.rules.size());

    // Pin maps
    (void)mkdir("/sys/fs/bpf/diting", 0755);
    pin_map_best_effort(skel->maps.drop_stats, DROP_STATS_PIN_PATH);
    pin_map_best_effort(skel->maps.watermark_level, "/sys/fs/bpf/diting/watermark_level");
    pin_map_best_effort(skel->maps.user_stats, USER_STATS_PIN_PATH);

    int fd_actions   = bpf_map__fd(skel->maps.monitor_actions);
    int fd_watermark = bpf_map__fd(skel->maps.watermark_level);
    int fd_ustats    = bpf_map__fd(skel->maps.user_stats);

    BaselineDB* baseline_db = nullptr;
    common_monitor_init(fd_actions, config, baseline_db_path, skip_boot_check, alert_mgr, baseline_db);

    // 水位背压控制器
    WatermarkBackpressure backpressure;
    MonitorContext mctx;
    mctx.alert_mgr    = &alert_mgr;
    mctx.backpressure = &backpressure;

    // ── 事件总线 + 落库管道 + 消费线程 ──────────────────────────
    EventBus bus(static_cast<size_t>(config.telemetry.queue_hi),
                 static_cast<size_t>(config.telemetry.queue_lo));
    ProcessTree proc_tree;
    Enricher enricher(proc_tree);
    EventStore* store = nullptr;
    if (config.telemetry.store) {
        store = new EventStore(config.telemetry.events_db, config.telemetry.batch_size,
                               config.telemetry.batch_ms);
        if (!store->ok()) {
            spdlog::warn("[event_store] 打开 {} 失败，降级为不落库", config.telemetry.events_db);
            delete store;
            store = nullptr;
        } else {
            spdlog::info("[event_store] telemetry store enabled, db={} batch_size={} batch_ms={} host_id={}",
                         config.telemetry.events_db, config.telemetry.batch_size,
                         config.telemetry.batch_ms, store->host_id());
        }
    }

    // ── 进程生命周期遥测（恒启动，供进程树 / 文件事件富化；失败降级）──
    // 须在消费线程创建前启动：消费线程 bootstrap 依赖 fork/exec/exit 事件流
    // 尽快就位，且 rt.proc_tree_on 需在线程启动前定型
    struct proc_watch_bpf *proc_skel = nullptr;
    struct ring_buffer *proc_rb = nullptr;
    proc_skel = process_monitor_start(&proc_rb, &bus);
    if (!proc_skel)
        spdlog::warn("[telemetry.process] proc_watch 启动失败，降级为无进程树富化");

    // ── DSL 规则引擎：do_monitor 入口已 fail-fast 加载并装入 g_rule_engine ──

    TelemetryRuntime rt;
    rt.bus       = &bus;
    rt.mctx      = &mctx;
    rt.tree      = &proc_tree;
    rt.enricher  = &enricher;
    rt.store     = store;
    rt.store_on  = (store != nullptr);
    rt.proc_tree_on = (proc_skel != nullptr);
    rt.running   = &running;
    rt.alert_mgr = &alert_mgr;
    rt.user_stats_fd = fd_ustats;
    std::thread consumer_thread(telemetry_consumer_main, &rt);

    spdlog::info("Monitoring started (ring buffer mode). Press Ctrl+C to stop.");

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &bus, nullptr);
    if (!rb) {
        spdlog::error("[bpf_program_error] Failed to create ring buffer");
        running = false;
        consumer_thread.join();
        delete store;
        if (baseline_db) delete baseline_db;
        lsm_file_bpf__destroy(skel);
        return 1;
    }

    backpressure.SetRingBuffer(rb);
    backpressure.SetNumCPUs(libbpf_num_possible_cpus());
    spdlog::info("[watermark] backpressure controller initialized (cpus={})",
                 libbpf_num_possible_cpus());

    // ── 网络遥测（telemetry.network / telemetry.dns 任一开启时启动；失败降级）──
    struct net_watch_bpf *net_skel = nullptr;
    struct ring_buffer *net_rb = nullptr;
    if (config.telemetry.network || config.telemetry.dns) {
        net_skel = network_monitor_start(&net_rb, config.telemetry.network,
                                         config.telemetry.dns, &bus);
        if (!net_skel)
            spdlog::warn("[telemetry.network] net_watch 启动失败，降级为仅文件监控");
    }

    // ── 权限遥测（仅 telemetry.privilege: true 时启动；失败降级）──
    struct priv_watch_bpf *priv_skel = nullptr;
    struct ring_buffer *priv_rb = nullptr;
    if (config.telemetry.privilege) {
        priv_skel = privilege_monitor_start(&priv_rb, &bus);
        if (!priv_skel)
            spdlog::warn("[telemetry.privilege] priv_watch 启动失败，降级为无权限遥测");
    }

    // epoll 同时等待文件事件 rb 与各路遥测 rb（任一遥测开启时启用）。
    // 以数组统一登记活跃 rb；同轮就绪时按数组顺序消费：
    // proc 先于 file——进程 exec 先于其文件事件产生，先消费 proc rb 可保证
    // 消费线程路由文件事件时进程树已捕获 exec（短寿进程白名单/富化依赖）；
    // net/priv 仍在 file 之后，保持进程事件先于网络事件入队（进程树时序）。
    struct RbEntry { int fd; struct ring_buffer* rb; };
    RbEntry rbs[4];
    int nrb = 0;
    if (proc_skel && proc_rb)
        rbs[nrb++] = {ring_buffer__epoll_fd(proc_rb), proc_rb};
    rbs[nrb++] = {ring_buffer__epoll_fd(rb), rb};
    if (net_skel && net_rb)
        rbs[nrb++] = {ring_buffer__epoll_fd(net_rb), net_rb};
    if (priv_skel && priv_rb)
        rbs[nrb++] = {ring_buffer__epoll_fd(priv_rb), priv_rb};

    int epollfd = -1;
    if (nrb > 1) {
        epollfd = epoll_create1(0);
        if (epollfd < 0) {
            spdlog::error("[bpf_program_error] epoll_create1 failed: {}", errno);
        } else {
            for (int i = 0; i < nrb; i++) {
                if (rbs[i].fd < 0)
                    continue;
                struct epoll_event ev {};
                ev.events = EPOLLIN;
                ev.data.fd = rbs[i].fd;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, rbs[i].fd, &ev) != 0)
                    spdlog::error("[bpf_program_error] epoll add rb fd={} failed: {}",
                                  rbs[i].fd, errno);
            }
        }
    }

    unsigned long long last_watermark_ns = now_monotonic_ns();
    unsigned long long last_ustats_ns    = now_monotonic_ns();
    while (running) {
        if (epollfd >= 0) {
            struct epoll_event evs[8];
            int n = epoll_wait(epollfd, evs, 8, 100);
            if (n < 0 && errno != EINTR) {
                spdlog::error("[bpf_program_error] Error waiting epoll: {}", errno);
                break;
            }
            for (int i = 0; i < n; i++) {
                for (int j = 0; j < nrb; j++) {
                    if (evs[i].data.fd == rbs[j].fd) {
                        ring_buffer__consume(rbs[j].rb);
                        break;
                    }
                }
            }
        } else {
            err = ring_buffer__poll(rb, 100);
            if (err < 0 && err != -EINTR) {
                spdlog::error("[bpf_program_error] Error polling ring buffer: {}", err);
                break;
            }
        }

        // 周期任务按时间触发（原按循环次数：高压下循环极快，触发频率远超设计
        // 语义，水位计算遍历全部 CPU ring + 16 次 map 更新会卡住 ring 消费，
        // 压测窗口 burst 期间导致内核 reserve 失败丢事件）
        const unsigned long long loop_now = now_monotonic_ns();
        if (loop_now - last_watermark_ns >= 1000000000ULL) {   // 1s
            backpressure.UpdateUtilization();
            __u32 wm_key   = 0;
            __u32 wm_value = static_cast<__u32>(backpressure.GetWatermarkLevel());
            bpf_map_update_elem(fd_watermark, &wm_key, &wm_value, BPF_ANY);
            last_watermark_ns = loop_now;
        }

        // 用户态计数器暴露：主循环周期同步（消费线程内层 pop 循环在高压下
        // 不退出，在那里同步会被饿死）。读 store 计数为跨线程近似读，仅用于可观测。
        if (loop_now - last_ustats_ns >= 1000000000ULL) {      // 1s
            sync_user_stats(fd_ustats, &bus, store, &mctx);
            last_ustats_ns = loop_now;
        }

        // SIGHUP 热加载：handler 只置标志，此处每轮检查（成功替换快照，失败保留旧配置）
        if (g_sighup_pending) {
            g_sighup_pending = 0;
            reload_monitor_config(config_path, alert_mgr);
        }
        // retention 已移至消费线程（避免与文件处理并发访问 AlertManager）
    }

    // 停机：通知消费线程退出并等待其 drain/落库收尾
    running = false;
    consumer_thread.join();

    spdlog::info("[watermark] final utilization={:.1f}% level={}",
                 backpressure.GetUtilization(),
                 WatermarkBackpressure::LevelToString(backpressure.GetWatermarkLevel()));

    spdlog::info("[service_stop] monitoring loop exited");
    spdlog::info("Monitoring stopped.");
    if (epollfd >= 0)
        close(epollfd);
    if (proc_skel)
        process_monitor_stop(proc_skel, proc_rb);
    if (priv_skel)
        privilege_monitor_stop(priv_skel, priv_rb);
    if (net_skel)
        network_monitor_stop(net_skel, net_rb);
    ring_buffer__free(rb);

    bpf_map__unpin(skel->maps.drop_stats, "/sys/fs/bpf/diting/drop_stats");
    bpf_map__unpin(skel->maps.watermark_level, "/sys/fs/bpf/diting/watermark_level");
    bpf_map__unpin(skel->maps.user_stats, "/sys/fs/bpf/diting/user_stats");
    lsm_file_bpf__destroy(skel);

    delete store;
    if (baseline_db) {
        delete baseline_db;
        g_inode_to_baseline.clear();
    }
    return 0;
}

// ══════════════════════════════════════════════════════════════════
// 路径 B：内核 5.7 — BPF LSM + perf event buffer
// ══════════════════════════════════════════════════════════════════
int do_monitor_perf(const Config& config, AlertManager &alert_mgr,
                           const std::string& config_path,
                           const std::string& baseline_db_path, bool skip_boot_check) {
    warn_telemetry_unavailable(config);

    struct lsm_file_perf_bpf *skel;
    int err;

    skel = lsm_file_perf_bpf__open();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open perf BPF skeleton");
        return 1;
    }

    // mmap_file hook 在 5.9 才引入
    if (skel->progs.file_mmap_hook && !kernel_at_least(5, 9)) {
        bpf_program__set_autoload(skel->progs.file_mmap_hook, false);
        spdlog::info("[bpf_compat] mmap_file hook disabled (kernel requires 5.9+)");
    }

    err = lsm_file_perf_bpf__load(skel);
    if (err) {
        // 同 ring buffer 路径：旧内核 verifier 不支持按值 STRUCT 参数
        // （path_chown 的 kuid_t/kgid_t），降级禁载 chown 钩子重试
        spdlog::warn("[bpf_compat] perf skeleton load failed ({}): "
                     "retry without path_chown hook (CHOWN detection degraded)", err);
        lsm_file_perf_bpf__destroy(skel);
        skel = lsm_file_perf_bpf__open();
        if (!skel) {
            spdlog::error("[bpf_program_error] Failed to reopen perf BPF skeleton");
            return 1;
        }
        if (skel->progs.file_mmap_hook && !kernel_at_least(5, 9))
            bpf_program__set_autoload(skel->progs.file_mmap_hook, false);
        bpf_program__set_autoload(skel->progs.file_chown_hook, false);
        err = lsm_file_perf_bpf__load(skel);
        if (err) {
            spdlog::error("[bpf_program_error] Failed to load perf BPF skeleton: {}", err);
            lsm_file_perf_bpf__destroy(skel);
            return 1;
        }
    }

    err = lsm_file_perf_bpf__attach(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to attach perf BPF program: {}", err);
        lsm_file_perf_bpf__destroy(skel);
        return 1;
    }
    spdlog::info("[bpf_program_loaded] BPF LSM (perf buffer) attached, kernel 5.7, {} rules",
                 config.rules.size());

    // Pin drop_stats
    (void)mkdir("/sys/fs/bpf/diting", 0755);
    pin_map_best_effort(skel->maps.drop_stats, DROP_STATS_PIN_PATH);
    pin_map_best_effort(skel->maps.user_stats, USER_STATS_PIN_PATH);

    int fd_actions = bpf_map__fd(skel->maps.monitor_actions);

    BaselineDB* baseline_db = nullptr;
    common_monitor_init(fd_actions, config, baseline_db_path, skip_boot_check, alert_mgr, baseline_db);

    // 无水位背压（perf buffer 无利用率查询）
    MonitorContext mctx;
    mctx.alert_mgr = &alert_mgr;
    mctx.user_stats_fd = bpf_map__fd(skel->maps.user_stats);

    spdlog::info("Monitoring started (perf buffer mode). Press Ctrl+C to stop.");

    struct perf_buffer *pb =
        new_perf_buffer_compat(bpf_map__fd(skel->maps.events), 64,
                               perf_event_cb, &mctx);
    if (!pb) {
        spdlog::error("[bpf_program_error] Failed to create perf buffer");
        if (baseline_db) delete baseline_db;
        lsm_file_perf_bpf__destroy(skel);
        return 1;
    }

    run_perf_buffer_loop(pb, mctx, alert_mgr, config_path);

    spdlog::info("[service_stop] monitoring loop exited");
    spdlog::info("Monitoring stopped.");
    perf_buffer__free(pb);

    bpf_map__unpin(skel->maps.drop_stats, "/sys/fs/bpf/diting/drop_stats");
    bpf_map__unpin(skel->maps.user_stats, "/sys/fs/bpf/diting/user_stats");
    lsm_file_perf_bpf__destroy(skel);

    if (baseline_db) {
        delete baseline_db;
        g_inode_to_baseline.clear();
    }
    return 0;
}

// ══════════════════════════════════════════════════════════════════
// 路径 C：内核 5.4 — kprobe + perf event buffer（仅告警，无法阻止）
// ══════════════════════════════════════════════════════════════════
int do_monitor_kprobe(const Config& config, AlertManager &alert_mgr,
                             const std::string& config_path,
                             const std::string& baseline_db_path, bool skip_boot_check) {
    warn_telemetry_unavailable(config);

    struct lsm_kprobe_bpf *skel;
    int err;

    spdlog::warn("[bpf_compat] kernel < 5.7, using kprobe mode — BLOCK actions degraded to ALERT only");

    skel = lsm_kprobe_bpf__open();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open kprobe BPF skeleton");
        return 1;
    }

    err = lsm_kprobe_bpf__load(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to load kprobe BPF skeleton: {}", err);
        lsm_kprobe_bpf__destroy(skel);
        return 1;
    }

    // 手动 attach kprobe 程序到内核函数
    struct bpf_link *link_perm   = bpf_program__attach_kprobe(skel->progs.kprobe_file_permission, false, "security_file_permission");
    struct bpf_link *link_chmod  = bpf_program__attach_kprobe(skel->progs.kprobe_path_chmod,     false, "security_path_chmod");
    struct bpf_link *link_chown  = bpf_program__attach_kprobe(skel->progs.kprobe_path_chown,     false, "security_path_chown");
    struct bpf_link *link_unlink = bpf_program__attach_kprobe(skel->progs.kprobe_inode_unlink,   false, "security_inode_unlink");
    struct bpf_link *link_rename = bpf_program__attach_kprobe(skel->progs.kprobe_inode_rename,   false, "security_inode_rename");

    if (!link_perm || !link_chmod || !link_chown || !link_unlink || !link_rename) {
        spdlog::error("[bpf_program_error] Failed to attach one or more kprobes");
        if (link_perm)   bpf_link__destroy(link_perm);
        if (link_chmod)  bpf_link__destroy(link_chmod);
        if (link_chown)  bpf_link__destroy(link_chown);
        if (link_unlink) bpf_link__destroy(link_unlink);
        if (link_rename) bpf_link__destroy(link_rename);
        lsm_kprobe_bpf__destroy(skel);
        return 1;
    }
    spdlog::info("[bpf_program_loaded] kprobe programs attached (5 kprobes), {} rules",
                 config.rules.size());

    // Pin drop_stats
    (void)mkdir("/sys/fs/bpf/diting", 0755);
    pin_map_best_effort(skel->maps.drop_stats, DROP_STATS_PIN_PATH);
    pin_map_best_effort(skel->maps.user_stats, USER_STATS_PIN_PATH);

    int fd_actions = bpf_map__fd(skel->maps.monitor_actions);

    BaselineDB* baseline_db = nullptr;
    common_monitor_init(fd_actions, config, baseline_db_path, skip_boot_check, alert_mgr, baseline_db);

    MonitorContext mctx;
    mctx.alert_mgr = &alert_mgr;
    mctx.user_stats_fd = bpf_map__fd(skel->maps.user_stats);

    spdlog::info("Monitoring started (kprobe mode, alert-only). Press Ctrl+C to stop.");

    struct perf_buffer *pb =
        new_perf_buffer_compat(bpf_map__fd(skel->maps.events), 64,
                               perf_event_cb, &mctx);
    if (!pb) {
        spdlog::error("[bpf_program_error] Failed to create perf buffer for kprobe");
        if (baseline_db) delete baseline_db;
        bpf_link__destroy(link_perm);
        bpf_link__destroy(link_chmod);
        bpf_link__destroy(link_chown);
        bpf_link__destroy(link_unlink);
        bpf_link__destroy(link_rename);
        lsm_kprobe_bpf__destroy(skel);
        return 1;
    }

    run_perf_buffer_loop(pb, mctx, alert_mgr, config_path);

    spdlog::info("[service_stop] monitoring loop exited");
    spdlog::info("Monitoring stopped.");
    perf_buffer__free(pb);

    bpf_map__unpin(skel->maps.drop_stats, "/sys/fs/bpf/diting/drop_stats");
    bpf_map__unpin(skel->maps.user_stats, "/sys/fs/bpf/diting/user_stats");
    bpf_link__destroy(link_perm);
    bpf_link__destroy(link_chmod);
    bpf_link__destroy(link_chown);
    bpf_link__destroy(link_unlink);
    bpf_link__destroy(link_rename);
    lsm_kprobe_bpf__destroy(skel);

    if (baseline_db) {
        delete baseline_db;
        g_inode_to_baseline.clear();
    }
    return 0;
}
