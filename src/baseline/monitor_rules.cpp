#include "monitor_internal.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <unistd.h>

std::shared_ptr<FileRuleTable> g_file_rules = std::make_shared<FileRuleTable>();
// 白名单不可变快照，与规则表同锁替换：读侧持锁取 const 引用，匹配无锁读表
std::shared_ptr<const WhitelistTable> g_whitelist_table =
    std::make_shared<const WhitelistTable>();
// DSL 规则引擎快照（W4）：与 FileRuleTable 同锁整代替换；空引擎求值一次分支即返回
std::shared_ptr<const detect::RuleEngine> g_rule_engine =
    std::make_shared<const detect::RuleEngine>();
std::shared_mutex g_file_rules_mtx;
WhitelistMatcher g_whitelist_matcher;

// ── DSL 文件规则 inode 登记（W7 D1 缺口一修复）────────────────────
// DSL condition 中 file.path 的 = / in 字面量路径，加载时登记进内核
// monitor_actions map（否则内核不产生该文件事件，规则永不触发）。
// 引用计数：多条 DSL 规则引用同一路径按 ino 合并计数；反登记仅当计数归零
// 且 config 规则 / 基线快照均不覆盖该 inode 时才从 map 删除（来源保护）。
// map_owner=false 表示登记时该 inode 已被 config/基线覆盖，map 条目非本模块写入。
std::unordered_map<unsigned long, DslInoReg> g_dsl_ino_refs;
// ino → 全路径（file_event_path 解析 DSL 专属 inode 的全路径；内核事件只带 basename）
std::unordered_map<unsigned long, std::string> g_dsl_ino_path;
// build_rule_engine 最近一次成功加载提取的登记候选（启动/热加载共用交接）
std::vector<detect::FilePathRef> g_dsl_pending_refs;
// monitor_actions map fd（common_monitor_init 赋值；SIGHUP 热加载反登记用）
int g_fd_actions = -1;

// 消费线程取引擎快照（shared_ptr 拷贝，锁内一次原子增减）
std::shared_ptr<const detect::RuleEngine> rule_engine_snapshot() {
    std::shared_lock<std::shared_mutex> lk(g_file_rules_mtx);
    return g_rule_engine;
}

// 启动/热加载共用：严格加载 rules_dir 并编译引擎；失败返回 nullptr。
// 调用方语义：启动路径 fail-fast 拒绝启动；热加载路径保留旧快照。
// W7 D1 起 enabled 且加载结果为 0 条规则同样视为失败——消灭"加载了 0 条
// 规则还正常跑"的空引擎路径（W6 D3/D4 静默空窗 2 天事故的同类变体）。
std::shared_ptr<const detect::RuleEngine> build_rule_engine(const RuleEngineConfig& cfg) {
    if (!cfg.enabled) {
        g_dsl_pending_refs.clear();
        return std::make_shared<const detect::RuleEngine>();
    }
    std::vector<detect::Rule> rules;
    std::string err;
    if (!detect::LoadRulesDir(cfg.rules_dir, rules, err)) {
        spdlog::error("[rule_engine] 规则加载失败: {}", err);
        return nullptr;
    }
    if (rules.empty()) {
        spdlog::error("[rule_engine] 规则加载失败: {} 下加载到 0 条规则"
                      "（rule_engine.enabled=true 时不允许空引擎；确认 rules_dir 或置 enabled: false）",
                      cfg.rules_dir);
        return nullptr;
    }
    auto engine = std::make_shared<detect::RuleEngine>();
    g_dsl_pending_refs = detect::ExtractFilePathRefs(rules); // 登记候选随成功加载交接
    if (!engine->Build(std::move(rules), err)) {
        spdlog::error("[rule_engine] 规则编译失败: {}", err);
        return nullptr;
    }
    return engine;
}

// 基线实时监控映射：inode -> CheckEntry（仅当 --db 模式下非空；启动时构建，热加载不变更）
std::unordered_map<unsigned long, CheckEntry> g_inode_to_baseline;

// DSL 文件路径登记/反登记同步（启动与热加载共用；W7 D1 任务 3/4）。
// 新集合 - 旧集合：新 ino 写入 map（已被 config/基线覆盖则只计数不改写）；
// 旧集合 - 新集合：计数归零且 config/基线均不覆盖时从 map 删除。
// 路径不可登记（含通配符 / 非绝对 / 不存在 / map 写失败）逐条 warn 降级——
// 该规则"加载成功但对应文件条件不生效"，不阻断其余规则（与任务 1 的
// 文件级解析失败 fail-fast 是两层语义，不混用）。
void dsl_sync_registrations(int fd_actions, const std::vector<detect::FilePathRef> &refs) {
    if (fd_actions < 0)
        return;
    std::unordered_map<unsigned long, std::pair<std::string, int>> wanted; // ino → (path, refs)
    for (const auto &ref : refs) {
        switch (detect::ClassifyPathRef(ref.path)) {
        case detect::PathRefClass::Glob:
            spdlog::warn("[rule_engine] 规则 {} 路径 {}: 含通配符（DSL v1 不支持 glob），"
                         "该文件条件不生效（规则已加载，其余条件不受影响）", ref.rule_name, ref.path);
            continue;
        case detect::PathRefClass::NotAbsolute:
            spdlog::warn("[rule_engine] 规则 {} 路径 {}: 非绝对路径，"
                         "该文件条件不生效（规则已加载，其余条件不受影响）", ref.rule_name, ref.path);
            continue;
        case detect::PathRefClass::Ok:
            break;
        }
        struct stat st;
        if (lstat(ref.path.c_str(), &st) != 0 || st.st_ino == 0) {
            spdlog::warn("[rule_engine] 规则 {} 路径 {}: 路径不存在（stat 失败: {}），"
                         "该文件条件不生效（规则已加载，其余条件不受影响）",
                         ref.rule_name, ref.path, strerror(errno));
            continue;
        }
        auto &w = wanted[st.st_ino];
        w.first = ref.path;
        w.second++;
    }

    std::unique_lock<std::shared_mutex> lk(g_file_rules_mtx);
    // 新增/更新登记
    for (const auto &[ino, w] : wanted) {
        auto it = g_dsl_ino_refs.find(ino);
        if (it != g_dsl_ino_refs.end()) {
            it->second.refs = w.second;
            g_dsl_ino_path[ino] = w.first;
            continue;
        }
        // 已被 config 规则或基线覆盖：事件已在流，沿用既有 map 条目的
        // events_mask（已知边界：既有条目掩码较窄时，其余事件类型本规则收不到），
        // 仅补路径映射与计数
        bool covered = g_file_rules->inode_to_rules.count(ino) > 0 ||
                       g_inode_to_baseline.count(ino) > 0;
        bool owner = false;
        if (!covered) {
            struct monitor_rule_set set {};
            struct monitor_rule v {};
            v.action = ACTION_ALERT;
            v.events_mask = EVENT_READ | EVENT_WRITE |
                            EVENT_MASK_BIT(EVENT_CHMOD) | EVENT_MASK_BIT(EVENT_CHOWN) |
                            EVENT_MASK_BIT(EVENT_UNLINK) | EVENT_MASK_BIT(EVENT_RENAME) |
                            EVENT_MASK_BIT(EVENT_MMAP);
            v.severity = SEVERITY_LOW; // 占位：告警级别由 DSL 规则 priority 决定
            set.rules[set.count++] = v;
            if (bpf_map_update_elem(fd_actions, &ino, &set, BPF_ANY) != 0) {
                spdlog::warn("[rule_engine] 路径 {} (ino {}): 内核 map 写入失败: {}"
                             "（容量满或 bpf 错误），该文件条件不生效",
                             w.first, ino, strerror(errno));
                continue;
            }
            owner = true;
        }
        g_dsl_ino_refs[ino] = DslInoReg{w.second, owner};
        g_dsl_ino_path[ino] = w.first;
    }
    // 反登记：计数归零且 config/基线均不覆盖才删除（同一路径多源引用不误删）
    for (auto it = g_dsl_ino_refs.begin(); it != g_dsl_ino_refs.end();) {
        if (wanted.count(it->first) > 0) {
            ++it;
            continue;
        }
        bool covered = g_file_rules->inode_to_rules.count(it->first) > 0 ||
                       g_inode_to_baseline.count(it->first) > 0;
        if (it->second.map_owner && !covered)
            bpf_map_delete_elem(fd_actions, &it->first);
        g_dsl_ino_path.erase(it->first);
        it = g_dsl_ino_refs.erase(it);
    }
    spdlog::info("[rule_engine] DSL 文件路径登记: {} inodes registered", g_dsl_ino_refs.size());
}

// ── SIGHUP 热加载 ─────────────────────────────────────────────
// handler 只置标志；主事件循环每轮检查发现置位即重解析配置：
// 成功原子替换规则表与白名单快照并清缓存，失败保留旧配置
volatile sig_atomic_t g_sighup_pending = 0;

void monitor_sighup_handler(int) {
    g_sighup_pending = 1;
}

void reload_monitor_config(const std::string& config_path, AlertManager& alert_mgr) {
    Config new_config;
    std::string err;
    if (!tryParseYamlFile(config_path, new_config, err)) {
        spdlog::error("[config_reload] 失败，保留旧配置: {}", err);
        return;
    }
    compute_inodes(new_config);
    auto new_rules = FileRuleTable::Build(new_config);
    auto new_wl = WhitelistTable::Build(new_config);
    // 规则引擎同步整代替换：加载失败整体保留旧快照（文件规则表也不换）
    auto new_engine = build_rule_engine(new_config.rule_engine);
    if (new_engine == nullptr) {
        spdlog::error("[config_reload] 规则引擎加载失败，保留旧配置");
        return;
    }
    {
        std::unique_lock<std::shared_mutex> lk(g_file_rules_mtx);
        g_file_rules = std::move(new_rules);
        g_whitelist_table = std::move(new_wl);
        g_rule_engine = std::move(new_engine);
    }
    g_whitelist_matcher.ClearCache();
    // DSL 文件规则 inode 登记同步（W7 D1）：按新规则集增删登记；
    // 覆盖判定用刚替换的新 config 规则表 + 基线（热加载不变更）快照
    dsl_sync_registrations(g_fd_actions, g_dsl_pending_refs);
    // notify 外发配置随热加载生效（min_level / webhook_url / silence_minutes）
    alert_mgr.UpdateNotifyConfig(new_config.notify);
    spdlog::info("config reloaded ({} rules)", new_config.rules.size());
}

// 60s 周期：各 rule 白名单抑制计数增量打一行 info（无增量不打）；
// 附告警节流抑制累计（M5-3 "已抑制 N 条" 对账口径，自进程启动累计不重置）。
void log_suppressed_stats(const AlertManager* alert_mgr) {
    for (const auto& [rule_id, n] : g_whitelist_matcher.GetAndResetSuppressed()) {
        if (n > 0)
            spdlog::info("[whitelist] suppressed: rule={} count={}", rule_id, n);
    }
    if (alert_mgr != nullptr && alert_mgr->ThrottledTotal() > 0) {
        spdlog::info("[alerts] throttled: total={}", alert_mgr->ThrottledTotal());
        for (const auto& [rule_id, n] : alert_mgr->ThrottledByRule())
            spdlog::info("[alerts] throttled: rule={} count={}", rule_id, n);
    }
    // 外发计数（W5 D4/D5）：有任一非零才打行
    if (alert_mgr != nullptr) {
        const NotifyStats ns = alert_mgr->GetNotifyStats();
        if (ns.sent > 0 || ns.failed > 0 || ns.suppressed > 0 || ns.dropped > 0 || ns.merged > 0) {
            spdlog::info("[notify] stats: sent={} failed={} suppressed={} dropped={} merged={}",
                         ns.sent, ns.failed, ns.suppressed, ns.dropped, ns.merged);
        }
    }
}
