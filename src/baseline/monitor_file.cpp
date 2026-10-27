#include "monitor.hpp"
#include "monitor_internal.hpp"
#include "monitor_baseline.hpp"
#include "process_tree.hpp"
#include "enricher.hpp"
#include "utils.hpp"
#include "container.hpp"
#include "commonfun.hpp"

#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

using json = nlohmann::json;

void on_violation_detected(const Rule& rule,
                           const std::string& file_path,
                           const std::string& actual_mode,
                           const std::string& proc_name,
                           int pid,
                           AlertManager& alert_mgr,
                           const FileActorContext* actor)
{
    // actor 非空（进程树命中）：user_name/uid 直接用 actor 值，跳过 /proc 读取；
    // actor 为空走现有 /proc 兜底（行为与现状一致）
    std::string uid;
    std::string user_name;
    if (actor != nullptr) {
        uid = std::to_string(actor->uid);
        user_name = actor->user_name;
    } else {
        user_name = ResolveUserInfoByPid(pid, uid);
    }

    // 1. 写日志
    spdlog::warn("VIOLATION: {} mode {} -> {} by {}/{} user={} uid={}",
                 file_path, mode_to_string(rule.check_expected), actual_mode, proc_name, pid,
                 user_name.empty() ? "unknown" : user_name,
                 uid.empty() ? "-" : uid);

    // 2. 节流窗口内不构建 AlertEvent：SendDingTalk 本来就不发不存，
    //    构建（含 ancestors JSON dump / NowString）纯属浪费（高频事件路径实测热点）；
    //    抑制计数在此入口记（不经 SendDingTalk，不会双计）
    if (alert_mgr.ThrottledNow(rule.id)) {
        alert_mgr.NoteThrottled(rule.id);
        return;
    }

    // 3. 发钉钉 + 自动落库（AlertManager 内部统一处理）
    AlertEvent evt;
    evt.rule_id      = rule.id;
    evt.rule_name    = rule.name;
    evt.severity     = severityToString(rule.severity);
    evt.file_path    = file_path;
    evt.expected     = mode_to_string(rule.check_expected);
    evt.actual       = actual_mode;
    evt.process_name = proc_name;
    evt.pid          = pid;
    evt.user_name    = user_name;
    evt.uid          = uid;
    evt.timestamp    = NowString();
    evt.event_type   = actual_mode;  // read / write
    evt.action_taken = actionToString(rule.monitor_action);
    if (actor != nullptr) {
        evt.exe          = actor->exe;
        evt.container_id = actor->container_id;
        evt.ancestors    = actor->ancestors_json;
    }

    alert_mgr.MaybeBoostForAi(evt);  // AI 升级（W6 D4）：命中资产则级别升一级
    alert_mgr.SendDingTalk(evt);
}

void on_check_mismatch_detected(const Rule& rule,
                                const std::string& file_path,
                                const std::string& proc_name,
                                int pid,
                                AlertManager& alert_mgr,
                                const FileActorContext* actor)
{
    if (!rule.has_check || rule.check_path.empty() || rule.check_path != file_path) {
        return;
    }

    struct stat st;
    if (stat(file_path.c_str(), &st) != 0) {
        return;
    }

    const mode_t actual_mode = st.st_mode & 0777;
    const bool expected_hash = !rule.check_hash.empty();
    const bool expected_perm = rule.check_expected != 0;

    // 文件可能在 stat 后读取前被删除，compute_sha256 抛异常时跳过本次比对
    std::string actual_hash;
    try {
        actual_hash = compute_sha256(const_cast<std::string&>(file_path));
    } catch (const std::exception &ex) {
        spdlog::debug("check mismatch skipped for {}: {}", file_path, ex.what());
        return;
    }

    bool permission_match = true;
    bool hash_match = true;

    if (expected_perm) {
        permission_match = (actual_mode == rule.check_expected);
    }
    if (expected_hash) {
        hash_match = (actual_hash == rule.check_hash);
    }

    if (permission_match && hash_match) {
        return;
    }

    std::string uid;
    std::string user_name;
    if (actor != nullptr) {
        uid = std::to_string(actor->uid);
        user_name = actor->user_name;
    } else {
        user_name = ResolveUserInfoByPid(pid, uid);
    }

    std::ostringstream msg;
    msg << "check mismatch detected by monitor";
    if (!permission_match) {
        msg << " permission=" << mode_to_string(actual_mode) << " expected=" << mode_to_string(rule.check_expected);
    }
    if (!hash_match) {
        msg << " hash=" << actual_hash << " expected=" << rule.check_hash;
    }

    spdlog::warn("[monitor_check_mismatch] {} process={} pid={} user={} uid={} file={}",
                 msg.str(), proc_name, pid,
                 user_name.empty() ? "unknown" : user_name,
                 uid.empty() ? "-" : uid,
                 file_path);

    AlertEvent evt;
    evt.rule_id      = rule.id;
    evt.rule_name    = rule.name;
    evt.severity     = severityToString(rule.severity);
    evt.file_path    = file_path;
    evt.expected     = (expected_perm ? mode_to_string(rule.check_expected) : "-");
    evt.actual       = (expected_perm ? mode_to_string(actual_mode) : "-");
    evt.process_name = proc_name;
    evt.pid          = pid;
    evt.user_name    = user_name;
    evt.uid          = uid;
    evt.timestamp    = NowString();
    evt.event_type   = "check_mismatch";
    evt.action_taken = actionToString(rule.monitor_action);

    if (!rule.check_hash.empty()) {
        evt.expected += "|hash=" + rule.check_hash;
        evt.actual += "|hash=" + actual_hash;
    }
    if (actor != nullptr) {
        evt.exe          = actor->exe;
        evt.container_id = actor->container_id;
        evt.ancestors    = actor->ancestors_json;
    }

    alert_mgr.MaybeBoostForAi(evt);  // AI 升级（W6 D4）
    alert_mgr.SendDingTalk(evt);
}

// ── chmod/chown 事件处理（--db 模式下）──────────────────────────────
// eBPF 拦截到 chmod/chown 后，直接用事件中的新值与基线比对
// 无需 stat 磁盘文件（LSM hook 在操作前触发，磁盘上仍是旧值）
static void handle_chmod_chown_event(const struct event *e,
                                      AlertManager& alert_mgr,
                                      const FileActorContext* actor) {
    auto it_bl = g_inode_to_baseline.find(e->ino);
    if (it_bl == g_inode_to_baseline.end())
        return;

    const CheckEntry& baseline = it_bl->second;
    const std::string& file_path = baseline.file_path;
    std::string proc_name(reinterpret_cast<const char*>(e->comm), 16);
    // 去除尾部 \0
    auto null_pos = proc_name.find('\0');
    if (null_pos != std::string::npos) proc_name.resize(null_pos);

    if (e->event_type == EVENT_CHMOD) {
        std::string actual_perm = mode_to_string(e->new_mode & 0777);
        if (actual_perm != baseline.permission) {
            BaselineDeviation dev;
            dev.event_type = "perm_changed";
            dev.severity   = "medium";
            dev.expected   = "mode=" + baseline.permission;
            dev.actual     = "mode=" + actual_perm;
            HandleBaselineDeviation(dev, file_path, proc_name, e->pid, alert_mgr,
                                    kBaselineRuleId, actor);
        }
    } else if (e->event_type == EVENT_CHOWN) {
        bool uid_diff = (static_cast<int64_t>(e->new_uid) != baseline.uid);
        bool gid_diff = (static_cast<int64_t>(e->new_gid) != baseline.gid);
        if (uid_diff || gid_diff) {
            BaselineDeviation dev;
            dev.event_type = "own_changed";
            dev.severity   = "medium";
            std::string exp_parts, act_parts;
            if (uid_diff) {
                exp_parts += "uid=" + std::to_string(baseline.uid);
                act_parts += "uid=" + std::to_string(e->new_uid);
            }
            if (gid_diff) {
                if (!exp_parts.empty()) exp_parts += ", ";
                exp_parts += "gid=" + std::to_string(baseline.gid);
                if (!act_parts.empty()) act_parts += ", ";
                act_parts += "gid=" + std::to_string(e->new_gid);
            }
            dev.expected = exp_parts;
            dev.actual   = act_parts;
            HandleBaselineDeviation(dev, file_path, proc_name, e->pid, alert_mgr,
                                    kBaselineRuleId, actor);
        }
    }
}

// ── 白名单匹配：从 FileActorContext.ancestors JSON 还原祖先 exe 链 ──
// ancestors 为 [{pid,comm,exe}] 自近及远 ≤8 层（Enricher::ancestors_of 产物）
static std::vector<std::string> actor_ancestor_exes(const json& ancestors) {
    std::vector<std::string> out;
    if (ancestors.is_array()) {
        for (const auto& a : ancestors) {
            if (a.contains("exe") && a["exe"].is_string())
                out.push_back(a["exe"].get<std::string>());
        }
    }
    return out;
}

// ── 核心事件处理逻辑 ────────────────────────────────────────────────
void process_event_core(struct event* e, MonitorContext* mctx,
                               const FileActorContext* actor) {
    AlertManager* alert_mgr = mctx->alert_mgr;

    // ── chmod/chown/unlink 实时检测（--db 模式下，eBPF 直接拦截）────────
    if (!g_inode_to_baseline.empty() && alert_mgr != nullptr) {
        if (e->event_type == EVENT_CHMOD || e->event_type == EVENT_CHOWN) {
            handle_chmod_chown_event(e, *alert_mgr, actor);
            return;
        }
        if (e->event_type == EVENT_UNLINK) {
            auto it_bl = g_inode_to_baseline.find(e->ino);
            if (it_bl != g_inode_to_baseline.end()) {
                const std::string& file_path = it_bl->second.file_path;
                std::string proc_name(reinterpret_cast<const char*>(e->comm), 16);
                auto null_pos = proc_name.find('\0');
                if (null_pos != std::string::npos) proc_name.resize(null_pos);
                BaselineDeviation dev;
                dev.event_type = "missing";
                dev.severity   = "high";
                dev.expected   = "file exists";
                dev.actual     = "file deleted (unlink detected by eBPF)";
                HandleBaselineDeviation(dev, file_path, proc_name, e->pid, *alert_mgr,
                                        kBaselineRuleId, actor);
            }
            return;
        }
    }

    // ── 原有 YAML 规则匹配逻辑（R13：同 inode 多规则逐条独立告警；M0-2 加白名单抑制决策点）
    // 持读锁保证热加载（写锁整体替换快照）期间 Rule/路径引用恒有效
    {
    std::shared_lock<std::shared_mutex> rules_lock(g_file_rules_mtx);
    const auto file_rules = g_file_rules;
    auto it_rules = file_rules->inode_to_rules.find(e->ino);
    if (it_rules != file_rules->inode_to_rules.end()) {
        auto it_path = file_rules->inode_to_path.find(e->ino);

        for (const Rule& rule : it_rules->second) {
        // 白名单抑制（M0-2）：命中则计数 + debug 留痕（rule/pid/exe/path），
        // 跳过本规则全部告警；未命中及 fail-closed 场景走原有告警流程，行为零变化。
        // exe/祖先优先用进程树 exec 时捕获的 actor（短寿进程 /proc 已回收，树数据
        // 更及时且与 /proc 等价）；actor 无 exe 退回 /proc 解析（fail-closed）
        if (!g_whitelist_table->empty()) {
            std::string exe;
            bool suppressed;
            if (actor != nullptr && !actor->exe.empty()) {
                static const json kNoAncestors = json::array();
                suppressed = g_whitelist_matcher.Match(*g_whitelist_table, rule,
                                                       e->pid, e->start_time, actor->exe,
                                                       actor_ancestor_exes(
                                                           actor->ancestors != nullptr
                                                               ? *actor->ancestors
                                                               : kNoAncestors),
                                                       &exe);
            } else {
                suppressed = g_whitelist_matcher.Match(*g_whitelist_table, rule, e->pid,
                                                       &exe);
            }
            if (suppressed) {
                spdlog::debug("[whitelist] suppressed: rule={} pid={} exe={} path={}",
                              rule.id, e->pid, exe,
                              it_path != file_rules->inode_to_path.end() ? it_path->second
                                                                         : std::string("?"));
                continue;
            }
        }

        if (it_path != file_rules->inode_to_path.end()) {
            const std::string &path = it_path->second;

            const std::string actual_event = ((e->mask & EVENT_READ) != 0) ? "read" : "write";
            if (alert_mgr != nullptr) {
                on_violation_detected(rule, path, actual_event, e->comm, e->pid, *alert_mgr,
                                      actor);
            }

            if (alert_mgr != nullptr && (e->mask & EVENT_WRITE) != 0) {
                on_check_mismatch_detected(rule, path, e->comm, e->pid, *alert_mgr, actor);
            }
        }
        }  // for rule

        auto it_hash = file_rules->inode_to_hashes.find(e->ino);
        if (it_hash != file_rules->inode_to_hashes.end() && !it_hash->second.empty()) {
            // 文件可能在读取瞬间被删除（如 unlink 事件后），compute_sha256
            // 抛异常时跳过本次哈希检查，避免异常穿透终止 monitor
            std::string current_hash;
            try {
                current_hash = compute_sha256(it_path->second);
            } catch (const std::exception &ex) {
                spdlog::debug("hash check skipped for {}: {}", it_path->second, ex.what());
                current_hash.clear();  // 视为一致，不告警
            }

            for (const std::string &expected_hash : it_hash->second) {
            if (!current_hash.empty() && current_hash != expected_hash) {
                std::ostringstream oss;
                oss << "[" << actionToString(static_cast<Action>(e->action)) << "] File modified! hash mismatch\n"
                    << "  path: " << it_path->second << "\n"
                    << "  pid: " << e->pid << "\n"
                    << "  comm: " << e->comm << "\n"
                    << "  expected_hash: " << expected_hash << "\n"
                    << "  current_hash:  " << current_hash << std::endl;
                spdlog::warn(oss.str());
            }
            }
        } else {
            // 无哈希基线的访问提示与 VIOLATION 行重复（同事件已告警），
            // 高频下 warn+flush 是消费线程热点，降为 debug 且不再逐条 flush
            std::ostringstream oss;
            oss << "[" << actionToString(static_cast<Action>(e->action)) << "] File access detected (no hash baseline)\n"
                << "  path: " << (it_path != file_rules->inode_to_path.end() ? it_path->second : "unknown") << "\n"
                << "  pid: " << e->pid << "\n"
                << "  comm: " << e->comm << std::endl;
            spdlog::debug(oss.str());
        }
    }
    }

    // ── 基线实时比对（--db 模式下）────────────────────────────────
    // 仅写/属性变更类事件触发：read 不改变文件完整性，且比对动作会读文件
    // 产生新 read 事件导致自激告警风暴；另加 2s 去抖防高频写重复比对。
    const bool is_attr_change = (e->event_type != 0);
    const bool is_write = ((e->mask & EVENT_WRITE) != 0);
    if (!g_inode_to_baseline.empty() && alert_mgr != nullptr && (is_attr_change || is_write)) {
        auto it_bl = g_inode_to_baseline.find(e->ino);
        if (it_bl != g_inode_to_baseline.end()) {
            static std::unordered_map<unsigned long, std::chrono::steady_clock::time_point> last_baseline_check;
            const auto now = std::chrono::steady_clock::now();
            auto it_t = last_baseline_check.find(e->ino);
            if (it_t != last_baseline_check.end() &&
                std::chrono::duration_cast<std::chrono::seconds>(now - it_t->second).count() < 2) {
                return;
            }
            last_baseline_check[e->ino] = now;

            const CheckEntry& baseline = it_bl->second;
            // 使用基线中存储的完整路径（不跟随 symlink）
            const std::string& full_path = baseline.file_path;

            std::vector<BaselineDeviation> devs = CompareWithBaseline(baseline, full_path);
            for (const auto& dev : devs) {
                HandleBaselineDeviation(dev, full_path, e->comm, e->pid, *alert_mgr,
                                        kBaselineRuleId, actor);
            }
        }
    }
}

// ── 文件事件进程上下文组装（仅消费线程调用）────────────────────────
// 按 (pid, start_time) 查进程树：命中填节点 uid/gid/ppid/exe/container_id
// （valid=true）；miss 时 uid/gid 用事件值、user_name 用 getpwuid(uid) 兜底，
// 其余留空（valid=false）。祖先链复用 Enricher 逻辑，自近及远 ≤8 层。
// getpwuid 每次调都走 NSS 读 /etc/passwd（无 nscd 时约几十 µs），高频事件
// 路径下是消费线程热点；uid→用户名运行期内不变，进程内缓存（仅消费线程访问）。
std::string cached_user_name(unsigned int uid) {
    static std::unordered_map<unsigned int, std::string> cache;
    auto it = cache.find(uid);
    if (it != cache.end())
        return it->second;
    std::string name;
    if (struct passwd* pw = getpwuid(static_cast<uid_t>(uid)))
        name = pw->pw_name;
    cache.emplace(uid, name);
    return name;
}

// 祖先链按 (pid, start_time) 缓存：同一进程实例的祖先链在其生命周期内不变
// （祖先 exec 造成的短暂 staleness 与 WhitelistMatcher 既有 (pid,start_time)
// 缓存语义一致）；map 有界防膨胀。start_time=0 不可键控时直接计算。
// dumped 为 a.dump() 的预计算串（空链为 ""，对应原 empty()?"":dump() 语义），
// 消费线程每事件引用一次，省去重复 dump。
struct AncestorsCached {
    json        a;
    std::string dumped;   // a.empty() 时为 ""
};
static const AncestorsCached& cached_ancestors_of(Enricher* enr, unsigned int pid,
                                                  unsigned long long start_time,
                                                  unsigned int ppid) {
    using Key = std::pair<unsigned int, unsigned long long>;
    static std::map<Key, AncestorsCached> cache;   // 仅消费线程访问
    if (start_time == 0) {
        thread_local AncestorsCached tmp;
        tmp.a = enr->ancestors_of(pid, ppid);
        tmp.dumped = tmp.a.empty() ? "" : tmp.a.dump();
        return tmp;
    }
    const Key k{pid, start_time};
    auto it = cache.find(k);
    if (it != cache.end())
        return it->second;
    if (cache.size() >= 4096)
        cache.clear();
    AncestorsCached e;
    e.a = enr->ancestors_of(pid, ppid);
    e.dumped = e.a.empty() ? "" : e.a.dump();
    return cache.emplace(k, std::move(e)).first->second;
}

FileActorContext build_file_actor(const struct event& e, TelemetryRuntime* rt) {
    FileActorContext actor;
    unsigned int ppid = 0;
    if (const ProcNode* node = rt->tree->find(e.pid, e.start_time)) {
        actor.uid = node->uid;
        actor.gid = node->gid;
        actor.ppid = node->ppid;
        actor.exe = node->exe_str();
        actor.container_id = node->container_id_str();
        actor.user_name = cached_user_name(node->uid);
        actor.valid = true;
        ppid = node->ppid;
    } else {
        actor.uid = e.uid;
        actor.gid = e.gid;
        actor.user_name = cached_user_name(e.uid);
    }
    const auto& anc = cached_ancestors_of(rt->enricher, e.pid, e.start_time, ppid);
    actor.ancestors      = anc.a.empty() ? nullptr : &anc.a;
    actor.ancestors_json = anc.dumped;
    return actor;
}

// ── 文件事件落库渲染（M0-1：CAT_FILE 对齐标准路径）────────────────
const char* file_event_kind(const struct event& e) {
    switch (e.event_type) {
    case EVENT_CHMOD:  return "file.chmod";
    case EVENT_CHOWN:  return "file.chown";
    case EVENT_UNLINK: return "file.unlink";
    case EVENT_RENAME: return "file.rename";
    case EVENT_MMAP:   return "file.mmap";
    default:
        if ((e.mask & EVENT_WRITE) != 0) return "file.write";
        if ((e.mask & EVENT_READ)  != 0) return "file.read";
        return "file.access";
    }
}

// 文件事件路径解析：优先基线完整路径（--db 模式，不跟随 symlink），
// 其次 YAML 规则路径，再次 DSL 登记路径（W7 D1）；均无退回事件自带文件名（仅 basename）。
std::string file_event_path(const struct event& e) {
    auto it_bl = g_inode_to_baseline.find(e.ino);
    if (it_bl != g_inode_to_baseline.end())
        return it_bl->second.file_path;
    std::shared_lock<std::shared_mutex> rules_lock(g_file_rules_mtx);
    auto it_path = g_file_rules->inode_to_path.find(e.ino);
    if (it_path != g_file_rules->inode_to_path.end())
        return it_path->second;
    auto it_dsl = g_dsl_ino_path.find(e.ino);
    if (it_dsl != g_dsl_ino_path.end())
        return it_dsl->second;
    return std::string(e.path);
}

// ── R10：CAT_FILE payload 直写 JSON 序列化 ─────────────────────────
// 输出与 nlohmann::json::dump() 逐字节一致（map 序键 / ensure_ascii=false /
// 无效 UTF-8 替换 U+FFFD），但跳过 json DOM 的 std::map 节点分配与销毁
// （压测下约占消费线程 40-50% CPU，是吞吐瓶颈的主因）。
namespace {

// Höhrmann UTF-8 DFA（与 nlohmann detail::serializer::decode 同一状态表，
// 逐字节行为一致：ACCEPT=0 / REJECT=1，其余为中间态）
inline std::uint8_t utf8_dfa_decode(std::uint8_t& state, std::uint32_t& codep,
                                    std::uint8_t byte) noexcept {
    static const std::uint8_t utf8d[400] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 00..1F
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 20..3F
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 40..5F
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 60..7F
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, // 80..9F
        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, // A0..BF
        8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // C0..DF
        0xA,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x4,0x3,0x3, // E0..EF
        0xB,0x6,0x6,0x6,0x5,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8, // F0..FF
        0x0,0x1,0x2,0x3,0x5,0x8,0x7,0x1,0x1,0x1,0x4,0x6,0x1,0x1,0x1,0x1, // s0
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1, // s1..s2
        1,2,1,1,1,1,1,2,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1, // s3..s4
        1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,3,1,1,1,1,1,1, // s5..s6
        1,3,1,1,1,1,1,3,1,3,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // s7..s8
    };
    const std::uint8_t type = utf8d[byte];
    codep = (state != 0) ? static_cast<std::uint32_t>((byte & 0x3Fu) | (codep << 6u))
                         : static_cast<std::uint32_t>((0xFFu >> type) & byte);
    state = utf8d[256u + state * 16u + type];
    return state;
}

// 追加 JSON 字符串字面量（含引号与转义），语义同 nlohmann dump_escaped
void append_json_string(std::string& out, const char* s, size_t n) {
    out.push_back('"');
    std::uint32_t codepoint = 0;
    std::uint8_t state = 0;
    size_t undumped = 0;   // 自上次 ACCEPT 以来追加的字节数
    for (size_t i = 0; i < n; ++i) {
        const auto byte = static_cast<std::uint8_t>(s[i]);
        const std::uint8_t st = utf8_dfa_decode(state, codepoint, byte);
        if (st == 1) {   // REJECT：丢弃半成品序列，替换 U+FFFD，当前字节重来
            out.resize(out.size() - undumped);
            if (undumped > 0)
                --i;
            out += "\xEF\xBF\xBD";
            undumped = 0;
            state = 0;
            continue;
        }
        if (st != 0) {   // 中间态：暂存原始字节
            out.push_back(static_cast<char>(byte));
            ++undumped;
            continue;
        }
        switch (codepoint) {
        case 0x08: out += "\\b"; break;
        case 0x09: out += "\\t"; break;
        case 0x0A: out += "\\n"; break;
        case 0x0C: out += "\\f"; break;
        case 0x0D: out += "\\r"; break;
        case 0x22: out += "\\\""; break;
        case 0x5C: out += "\\\\"; break;
        default:
            if (codepoint <= 0x1F) {
                char buf[7];
                std::snprintf(buf, sizeof(buf), "\\u%04x",
                              static_cast<unsigned>(codepoint));
                out.append(buf, 6);
            } else {
                out.push_back(static_cast<char>(byte));
            }
        }
        undumped = 0;
    }
    out.push_back('"');
}

inline void append_json_string(std::string& out, const std::string& s) {
    append_json_string(out, s.data(), s.size());
}

inline void append_u64(std::string& out, unsigned long long v) {
    char buf[20];
    int len = std::snprintf(buf, sizeof(buf), "%llu", v);
    out.append(buf, static_cast<size_t>(len));
}

}  // namespace

// 文件事件落库 payload 直写（键序同 nlohmann map 序），同时回填 rec 索引列；
// actor 为空（proc_watch 未启动）时 uid/gid 退回事件值、exe/container 省略、
// ancestors 退回 Enricher 兜底（与 R10 前 enrich 路径一致）。
void render_file_payload(const struct event& e, struct EventRecord& rec,
                                const FileActorContext* actor, Enricher* enr,
                                std::string& out) {
    out.clear();
    out.reserve(512);
    out.push_back('{');
    if (actor != nullptr && !actor->container_id.empty()) {
        out += "\"container\":{\"container_id\":";
        append_json_string(out, actor->container_id);
        out += "},";
    }
    out += "\"event_type\":";
    append_json_string(out, file_event_kind(e), std::strlen(file_event_kind(e)));

    out += ",\"file\":{\"action\":";
    append_json_string(out, actionToString(static_cast<Action>(e.action)));
    out += ",\"ino\":";
    append_u64(out, e.ino);
    out += ",\"mask\":";
    append_u64(out, static_cast<unsigned long long>(e.mask));
    if (e.event_type == EVENT_CHOWN) {
        out += ",\"new_gid\":";
        append_u64(out, e.new_gid);
    }
    if (e.event_type == EVENT_CHMOD) {
        out += ",\"new_mode\":";
        append_json_string(out, mode_to_string(e.new_mode & 07777));
    }
    if (e.event_type == EVENT_CHOWN) {
        out += ",\"new_uid\":";
        append_u64(out, e.new_uid);
    }
    out += ",\"path\":";
    append_json_string(out, file_event_path(e));

    out += "},\"process\":{\"ancestors\":";
    if (actor != nullptr)
        out += actor->ancestors_json.empty() ? "[]" : actor->ancestors_json;
    else if (enr != nullptr)
        out += enr->ancestors_of(rec.pid, rec.ppid).dump();
    else
        out += "[]";
    out += ",\"comm\":";
    {
        std::string comm(reinterpret_cast<const char*>(e.comm), sizeof(e.comm));
        auto comm_end = comm.find('\0');
        if (comm_end != std::string::npos)
            comm.resize(comm_end);
        append_json_string(out, comm);
    }
    if (actor != nullptr && !actor->exe.empty()) {
        out += ",\"exe\":";
        append_json_string(out, actor->exe);
    }
    out += ",\"gid\":";
    append_u64(out, (actor != nullptr) ? actor->gid : e.gid);
    out += ",\"pid\":";
    append_u64(out, e.pid);
    if (actor != nullptr && actor->ppid > 0) {
        out += ",\"ppid\":";
        append_u64(out, actor->ppid);
    }
    out += ",\"uid\":";
    append_u64(out, (actor != nullptr) ? actor->uid : e.uid);
    out += "},\"ts\":";
    append_u64(out, rec.ts_ns);
    out.push_back('}');

    rec.uid  = (actor != nullptr) ? actor->uid : e.uid;
    rec.ppid = (actor != nullptr) ? actor->ppid : 0;
    if (actor != nullptr) {
        record_set_str(rec.exe, sizeof(rec.exe), actor->exe.c_str(), actor->exe.size());
        record_set_str(rec.container_id, sizeof(rec.container_id),
                       actor->container_id.c_str(), actor->container_id.size());
    }
}
