#include "monitor.hpp"
#include "monitor_internal.hpp"
#include "monitor_process.hpp"
#include "commonfun.hpp"
#include "utils.hpp"
#include "process_tree.hpp"
#include "enricher.hpp"
#include "proc_event.h"
#include "net_event.h"
#include "priv_event.h"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

using json = nlohmann::json;

// ── DSL 规则引擎接入（W4 D4）：仅消费线程调用，引擎快照只读 ─────────
// rule_id = "dsl." + slug（小写字母数字保留，其余折叠为单个 '_'）
static std::string dsl_rule_id(const std::string& name) {
    std::string id = "dsl.";
    bool last_us = false;
    for (const unsigned char c : name) {
        if (std::isalnum(c)) {
            id += static_cast<char>(std::tolower(c));
            last_us = false;
        } else if (!last_us) {
            id += '_';
            last_us = true;
        }
    }
    while (!id.empty() && id.back() == '_')
        id.pop_back();
    return id;
}

// 祖先链 json [{pid,comm,exe}] → EventView 视图（string_view 引用 json 内部
// 存储，事件处理期内有效）
static void fill_ancestors_view(const json& anc, std::vector<detect::AncestorView>& out) {
    out.clear();
    if (!anc.is_array())
        return;
    for (const auto& a : anc) {
        detect::AncestorView av;
        if (a.contains("pid") && a["pid"].is_number())
            av.pid = a["pid"].get<long long>();
        if (a.contains("comm") && a["comm"].is_string()) {
            const auto& s = a["comm"].get_ref<const std::string&>();
            av.comm = std::string_view(s.data(), s.size());
        }
        if (a.contains("exe") && a["exe"].is_string()) {
            const auto& s = a["exe"].get_ref<const std::string&>();
            av.exe = std::string_view(s.data(), s.size());
        }
        out.push_back(av);
    }
}

// 命中后构造 AlertEvent 走 AlertManager 统一入口（节流/落库/钉钉与 FIM 一致）
static void send_dsl_alert(const detect::Rule& rule, const std::string& output,
                           const detect::EventView& view, const std::string& file_path,
                           const std::string& user_name, const std::string& ancestors_json,
                           AlertManager* alert_mgr) {
    const std::string rule_id = dsl_rule_id(rule.name);
    // 节流窗口内跳过 AlertEvent 构建（与 on_violation_detected 同一考量）；
    // 抑制计数在此入口记（不经 SendDingTalk，不会双计）
    if (alert_mgr->ThrottledNow(rule_id)) {
        alert_mgr->NoteThrottled(rule_id);
        return;
    }

    AlertEvent evt;
    evt.rule_id      = rule_id;
    evt.rule_name    = rule.name;
    evt.severity     = rule.priority;
    evt.file_path    = file_path;    // alerts.file_path 列 NOT NULL：file 事件取路径，exec 取 exe
    evt.actual       = output;
    evt.process_name = std::string(view.comm);
    evt.pid          = static_cast<int>(view.pid);
    evt.user_name    = user_name;
    evt.uid          = std::to_string(view.uid);
    evt.timestamp    = NowString();
    evt.event_type   = std::string(view.event_type);
    evt.action_taken = "alert";
    evt.exe          = std::string(view.exe);
    evt.container_id = std::string(view.container_id);
    evt.ancestors    = ancestors_json;
    for (size_t i = 0; i < rule.attack.size(); ++i) {
        if (i > 0)
            evt.attack += ',';
        evt.attack += rule.attack[i];
    }
    alert_mgr->MaybeBoostForAi(evt);  // AI 升级（W6 D4）
    alert_mgr->SendDingTalk(evt);
}

// 文件事件求值：CAT_FILE 分支 build_file_actor 之后、store->Append 之前调用
void eval_rules_on_file_event(const struct event& fe, const FileActorContext* actor,
                                     TelemetryRuntime* rt) {
    const auto engine = rule_engine_snapshot();
    if (engine->rule_count() == 0 || rt->alert_mgr == nullptr)
        return;

    const std::string path = file_event_path(fe);
    const std::string action = actionToString(static_cast<Action>(fe.action));
    std::string new_mode;
    if (fe.event_type == EVENT_CHMOD)
        new_mode = mode_to_string(fe.new_mode & 07777);

    detect::EventView view;
    view.event_type = file_event_kind(fe);
    view.pid  = fe.pid;
    view.ppid = (actor != nullptr) ? actor->ppid : 0;
    view.uid  = (actor != nullptr) ? actor->uid : fe.uid;
    view.gid  = (actor != nullptr) ? actor->gid : fe.gid;
    view.comm = std::string_view(fe.comm, strnlen(fe.comm, sizeof(fe.comm)));
    if (actor != nullptr) {
        view.exe = actor->exe;
        view.container_id = actor->container_id;
    }
    view.has_file = true;
    view.file_path   = path;
    view.file_action = action;
    view.file_new_mode = new_mode;
    view.file_ino     = static_cast<long long>(fe.ino);
    view.file_mask    = fe.mask;
    view.file_new_uid = fe.new_uid;
    view.file_new_gid = fe.new_gid;
    if (actor != nullptr && actor->ancestors != nullptr)
        fill_ancestors_view(*actor->ancestors, view.ancestors);

    detect::MatchResult m;
    if (!engine->Evaluate(view, m))
        return;

    std::string user_name;
    if (actor != nullptr) {
        user_name = actor->user_name;
    } else {
        std::string uid_str;
        user_name = ResolveUserInfoByPid(static_cast<int>(fe.pid), uid_str);
    }
    send_dsl_alert(*m.rule, m.output, view, path, user_name,
                   (actor != nullptr) ? actor->ancestors_json : std::string(),
                   rt->alert_mgr);
}

// exec 事件求值：CAT_PROCESS 分支 tree->apply 之后调用（不依赖 store 开关）
void eval_rules_on_exec_event(const struct proc_event& pe, TelemetryRuntime* rt) {
    const auto engine = rule_engine_snapshot();
    if (engine->rule_count() == 0 || rt->alert_mgr == nullptr)
        return;

    std::string exe;
    std::string container_id;
    unsigned int uid = pe.uid;
    if (const ProcNode* node = rt->tree->find(pe.pid, pe.start_time)) {
        exe = node->exe_str();
        container_id = node->container_id_str();
        uid = node->uid;
    }
    if (exe.empty())
        exe.assign(pe.exe, strnlen(pe.exe, sizeof(pe.exe)));

    detect::EventView view;
    view.event_type = "process.exec";
    view.pid  = pe.pid;
    view.ppid = pe.ppid;
    view.uid  = uid;
    view.gid  = pe.gid;
    view.comm = std::string_view(pe.comm, strnlen(pe.comm, sizeof(pe.comm)));
    view.exe  = exe;
    view.container_id = container_id;
    // cmdline：NUL 分隔原始字节 → 空格拼接（与落库渲染同一语义）；
    // 局部串存活至本函数结束，覆盖 Evaluate 与 output 模板插值
    const std::string cmdline = proc_cmdline_join(pe.cmdline, sizeof(pe.cmdline));
    view.cmdline = cmdline;
    const json anc = rt->enricher->ancestors_of(pe.pid, pe.ppid);
    fill_ancestors_view(anc, view.ancestors);

    detect::MatchResult m;
    // W8 S3 case-07 竞态修复兜底用：事件自带 filename（exec 时刻 tracepoint 捕获，
    // 无 /proc 再 exec 竞态）；声明在函数作用域，保证 view.exe 引用存活至告警发送
    const std::string event_exe(pe.exe, strnlen(pe.exe, sizeof(pe.exe)));
    if (!engine->Evaluate(view, m)) {
        // W8 S3 case-07 竞态修复：exe 取自消费时 /proc/<pid>/exe 解析，短寿进程
        // 原地再 exec（如 bash -c <cmd> 的末命令优化，同 pid 连续两次 exec）时，
        // 消费侧读到的是再 exec 之后的新映像（实测 bash exec 事件被渲染成
        // /usr/bin/id），导致 exe 名单类规则漏报。事件自带的 pe.exe 是
        // tracepoint 在 exec 时刻捕获的 filename，无此竞态；未命中且两者
        // 不一致时以 pe.exe 复评一次（G8 单命中不受影响：仅在未命中时复评）。
        if (event_exe.empty() || event_exe == exe) {
            if (exe.find("bash") != std::string::npos ||
                exe.find("/sh") != std::string::npos ||
                exe.find("dash") != std::string::npos) {
                spdlog::debug("[exec_eval] shell miss: exe={} comm={} ppid={} anc={}",
                              exe, view.comm, pe.ppid, anc.dump());
            }
            return;
        }
        spdlog::info("[exec_eval] exe 竞态兜底复评: resolved={} event={} pid={}",
                     exe, event_exe, pe.pid);
        view.exe = event_exe;
        if (!engine->Evaluate(view, m))
            return;
        exe = event_exe;
    }

    send_dsl_alert(*m.rule, m.output, view, exe, cached_user_name(uid),
                   anc.empty() ? std::string() : anc.dump(), rt->alert_mgr);
}

// network/dns 事件求值：render_network_event 之后调用（不依赖 store 开关）。
// view 的 string_view 引用 j 与 rec 内部存储，二者在调用期间存活。
void eval_rules_on_net_event(const struct net_event& ne, const EventRecord& rec,
                                    const json& j, TelemetryRuntime* rt) {
    const auto engine = rule_engine_snapshot();
    if (engine->rule_count() == 0 || rt->alert_mgr == nullptr)
        return;

    detect::EventView view;
    view.event_type = j["event_type"].get_ref<const std::string&>();
    view.pid  = ne.pid;
    view.ppid = ne.ppid;
    view.uid  = ne.uid;
    view.gid  = ne.gid;
    view.comm = std::string_view(ne.comm, strnlen(ne.comm, sizeof(ne.comm)));
    view.exe  = std::string_view(rec.exe, strnlen(rec.exe, sizeof(rec.exe)));
    view.container_id =
        std::string_view(rec.container_id, strnlen(rec.container_id, sizeof(rec.container_id)));
    if (ne.event_kind == NET_EVENT_DNS) {
        const json& d = j["dns"];
        view.has_dns    = true;
        view.dns_domain = d["domain"].get_ref<const std::string&>();
        view.dns_qtype  = d["qtype"].get<long long>();
    } else {
        const json& n = j["network"];
        view.has_network  = true;
        view.net_sip      = n["sip"].get_ref<const std::string&>();
        view.net_dip      = n["dip"].get_ref<const std::string&>();
        view.net_family   = n["family"].get<long long>();
        view.net_protocol = n["protocol"].get<long long>();
        view.net_sport    = n["sport"].get<long long>();
        view.net_dport    = n["dport"].get<long long>();
    }
    const json anc = rt->enricher->ancestors_of(ne.pid, ne.ppid);
    fill_ancestors_view(anc, view.ancestors);

    detect::MatchResult m;
    if (!engine->Evaluate(view, m))
        return;
    send_dsl_alert(*m.rule, m.output, view, std::string(view.exe), cached_user_name(ne.uid),
                   anc.empty() ? std::string() : anc.dump(), rt->alert_mgr);
}

// priv/ns 事件求值：render_privilege_event 之后调用（不依赖 store 开关）。
// priv_kind >= PRIV_KIND_MOUNT 为命名空间事件（ns.* 字段族），其余为权限事件。
void eval_rules_on_priv_event(const struct priv_event& pe, const EventRecord& rec,
                                     const json& j, TelemetryRuntime* rt) {
    const auto engine = rule_engine_snapshot();
    if (engine->rule_count() == 0 || rt->alert_mgr == nullptr)
        return;

    detect::EventView view;
    view.event_type = j["event_type"].get_ref<const std::string&>();
    view.pid  = pe.pid;
    view.ppid = pe.ppid;
    view.uid  = pe.uid;
    view.gid  = pe.gid;
    view.comm = std::string_view(pe.comm, strnlen(pe.comm, sizeof(pe.comm)));
    view.exe  = std::string_view(rec.exe, strnlen(rec.exe, sizeof(rec.exe)));
    view.container_id =
        std::string_view(rec.container_id, strnlen(rec.container_id, sizeof(rec.container_id)));
    if (pe.priv_kind >= PRIV_KIND_MOUNT) {
        const json& n = j["ns"];
        view.has_ns = true;
        if (n.contains("source"))
            view.ns_source = n["source"].get_ref<const std::string&>();
        if (n.contains("target"))
            view.ns_target = n["target"].get_ref<const std::string&>();
        if (n.contains("fstype"))
            view.ns_fstype = n["fstype"].get_ref<const std::string&>();
        if (n.contains("flags"))
            view.ns_flags = n["flags"].get<long long>();
        if (n.contains("fd"))
            view.ns_fd = n["fd"].get<long long>();
        if (n.contains("nstype"))
            view.ns_nstype = n["nstype"].get<long long>();
        if (n.contains("nstype_name"))
            view.ns_nstype_name = n["nstype_name"].get_ref<const std::string&>();
        if (n.contains("target_ns"))
            view.ns_target_ns = n["target_ns"].get_ref<const std::string&>();
        if (n.contains("names")) {
            // names 元素为字符串（未知名位以数值入数组，非字符串元素跳过）
            for (const auto& e : n["names"]) {
                if (e.is_string())
                    view.ns_names.push_back(e.get_ref<const std::string&>());
            }
        }
    } else {
        const json& p = j["priv"];
        view.has_priv = true;
        if (p.contains("target_id"))
            view.priv_target_id = p["target_id"].get<long long>();
        if (p.contains("effective_lo"))
            view.priv_effective_lo = p["effective_lo"].get<long long>();
        if (p.contains("request"))
            view.priv_request = p["request"].get_ref<const std::string&>();
        if (p.contains("request_value"))
            view.priv_request_value = p["request_value"].get<long long>();
        if (p.contains("target_pid"))
            view.priv_target_pid = p["target_pid"].get<long long>();
        if (p.contains("name"))
            view.priv_name = p["name"].get_ref<const std::string&>();
    }
    const json anc = rt->enricher->ancestors_of(pe.pid, pe.ppid);
    fill_ancestors_view(anc, view.ancestors);

    detect::MatchResult m;
    if (!engine->Evaluate(view, m))
        return;
    send_dsl_alert(*m.rule, m.output, view, std::string(view.exe), cached_user_name(pe.uid),
                   anc.empty() ? std::string() : anc.dump(), rt->alert_mgr);
}
