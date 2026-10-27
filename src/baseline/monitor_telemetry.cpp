#include "monitor_internal.hpp"
#include "monitor_network.hpp"
#include "monitor_process.hpp"
#include "monitor_privilege.hpp"
#include "event_bus.hpp"
#include "event_store.hpp"
#include "process_tree.hpp"
#include "enricher.hpp"
#include "proc_event.h"
#include "net_event.h"
#include "priv_event.h"

#include <cstring>
#include <thread>
#include <unistd.h>

#include <malloc.h>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

using json = nlohmann::json;

// ══════════════════════════════════════════════════════════════════
// 遥测消费线程：从事件总线拉取事件并路由
// ══════════════════════════════════════════════════════════════════

// 路由单条事件：file→查进程树拼进程上下文后回原处理函数（告警富化 exe/
// container_id/ancestors，树关闭时行为与现状一致；store 开启时渲染 JSON、
// 富化祖先链并落库）、process→先更新进程树（exec 另落库）、
// network/dns/priv/ns→渲染 JSON 走原日志输出并过规则引擎求值（W7 G3 接入），
// store 开启时富化祖先链并落库。
static void route_event(EventRecord& rec, TelemetryRuntime* rt) {
    // 排队延迟：dequeue 时间 - 入队时间
    const unsigned long long now = now_monotonic_ns();
    if (now >= rec.enqueue_ts_ns)
        rt->bus->record_queue_latency(now - rec.enqueue_ts_ns);

    switch (rec.category) {
    case CAT_FILE: {
        struct event fe;
        memcpy(&fe, rec.payload_raw, sizeof(fe));
        // 进程树开启时按 (pid, start_time) 查树拼进程上下文再处理（告警富化）；
        // 树关闭（proc_watch 启动失败/旧内核路径）传 nullptr，行为与现状一致。
        FileActorContext actor;
        const FileActorContext* actor_ptr = nullptr;
        if (rt->proc_tree_on) {
            actor = build_file_actor(fe, rt);
            actor_ptr = &actor;
        }
        process_event_core(&fe, rt->mctx, actor_ptr);
        eval_rules_on_file_event(fe, actor_ptr, rt);
        if (rt->store_on) {
            // 读/写（file_permission）事件 event_type=0，按 mask 归一 action 便于检索
            if (fe.event_type == 0)
                rec.action = (fe.mask & EVENT_WRITE) ? EVENT_WRITE : EVENT_READ;
            // R10：payload 直写 JSON（与 nlohmann dump 逐字节一致），
            // 祖先链用 build_file_actor 预序列化串；actor 为空退回 Enricher 兜底
            // R13：渲染 JSON 不再写回槽位，随 Append() 直接传给 EventStore
            thread_local std::string payload;   // 仅消费线程，复用缓冲
            render_file_payload(fe, rec, actor_ptr, rt->enricher, payload);
            rt->store->Append(rec, payload.c_str(), payload.size());
        }
        break;
    }
    case CAT_PROCESS: {
        struct proc_event pe;
        memcpy(&pe, rec.payload_raw, sizeof(pe));
        rt->tree->apply(pe);   // fork/exec/exit 维护进程树（单线程无锁）
        if (pe.kind == PROC_KIND_EXEC) {
            eval_rules_on_exec_event(pe, rt);   // 规则引擎求值不依赖 store 开关
            if (rt->store_on) {
                json j;
                render_process_exec_event(pe, rec, j);
                rt->enricher->enrich(rec, j);
                const std::string payload = j.dump();
                rt->store->Append(rec, payload.c_str(), payload.size());
            }
        }
        break;
    }
    case CAT_NETWORK:
    case CAT_DNS: {
        struct net_event ne;
        memcpy(&ne, rec.payload_raw, sizeof(ne));
        json j;
        render_network_event(ne, rec, j);
        spdlog::info("{}", j.dump());   // 与迁移前逐字节一致
        eval_rules_on_net_event(ne, rec, j, rt);   // 规则引擎求值不依赖 store 开关
        if (rt->store_on) {
            rt->enricher->enrich(rec, j);
            const std::string payload = j.dump();
            rt->store->Append(rec, payload.c_str(), payload.size());
        }
        break;
    }
    case CAT_PRIV:
    case CAT_NS: {
        struct priv_event pe;
        memcpy(&pe, rec.payload_raw, sizeof(pe));
        json j;
        render_privilege_event(pe, rec, j);
        spdlog::info("{}", j.dump());   // 与迁移前逐字节一致
        eval_rules_on_priv_event(pe, rec, j, rt);   // 规则引擎求值不依赖 store 开关
        if (rt->store_on) {
            rt->enricher->enrich(rec, j);
            const std::string payload = j.dump();
            rt->store->Append(rec, payload.c_str(), payload.size());
        }
        break;
    }
    default:
        break;
    }
}

// 事件内容（cmdline/comm/路径）是攻击者可控的原始字节，渲染/富化任何一环
// 抛异常（如 nlohmann 非法 UTF-8 type_error）都不能终止消费线程——
// W8 G21 实测一条截断 UTF-8 的 cmdline 把 monitor 整体打挂。单事件跳过。
static void route_event_guarded(EventRecord& rec, TelemetryRuntime* rt) {
    try {
        route_event(rec, rt);
    } catch (const std::exception& ex) {
        spdlog::error("[consumer] 事件渲染失败已跳过 (category={} pid={}): {}",
                      static_cast<int>(rec.category), rec.pid, ex.what());
    }
}

// 消费线程主循环：严格先拉 hi 再拉 lo；驱动落库批量刷新、延迟统计（60s）、
// drop 计数日志（30s）、tombstone sweep（60s）、告警 retention（3600s）。
void telemetry_consumer_main(TelemetryRuntime* rt) {
    // 进程树恒启用（store 关闭也需要：文件事件告警进程上下文富化依赖），
    // bootstrap 扫 /proc 建初始树（含 uid/gid、容器 ID）
    rt->tree->bootstrap();

    unsigned long long last_stats     = now_monotonic_ns();
    unsigned long long last_drop      = now_monotonic_ns();
    unsigned long long last_sweep     = now_monotonic_ns();
    unsigned long long last_retention = now_monotonic_ns();
    unsigned long long last_wl_stats  = now_monotonic_ns();
    unsigned long long last_drop_total = rt->bus->drop_count_total();
    // R13：空闲自适应退避——连续空转时 200us→2ms 指数退避，有事件即复位。
    // 压测下循环从不空转，吞吐路径零影响；空闲唤醒 5000/s→~500/s（CPU 优化）。
    long idle_backoff_ns = 200000;

    while (*rt->running) {
        bool did_work = false;
        EventRecord rec;
        while (rt->bus->try_pop_hi(rec)) {
            route_event_guarded(rec, rt);
            did_work = true;
        }
        while (rt->bus->try_pop_lo(rec)) {
            route_event_guarded(rec, rt);
            did_work = true;
        }
        if (did_work)
            idle_backoff_ns = 200000;

        if (rt->store)
            rt->store->FlushIfDue();

        const unsigned long long now = now_monotonic_ns();

        // 延迟统计：每 60s 有流量时打一行
        if (now - last_stats >= 60000000000ULL) {
            const auto q = rt->bus->queue_latency_summary();
            if (q.valid) {
                if (rt->store) {
                    const auto e = rt->store->e2e_latency_summary();
                    spdlog::info("[event_bus] stats: queue avg={:.1f}us p95={}us | e2e avg={:.1f}us p95={}us (samples={})",
                                 q.avg_us, q.p95_us, e.avg_us, e.p95_us, q.count);
                } else {
                    spdlog::info("[event_bus] stats: queue avg={:.1f}us p95={}us (samples={})",
                                 q.avg_us, q.p95_us, q.count);
                }
            }
            last_stats = now;
        }

        // 白名单抑制计数 + 告警节流抑制累计：每 60s 打一行
        if (now - last_wl_stats >= 60000000000ULL) {
            log_suppressed_stats(rt->alert_mgr);
            last_wl_stats = now;
        }

        // drop 计数：每 30s 有增量打一行
        if (now - last_drop >= 30000000000ULL) {
            const unsigned long long total = rt->bus->drop_count_total();
            if (total > last_drop_total) {
                spdlog::warn("[event_store] drops: hi(file={} ctrl={}) lo(net={} dns={}) total={}",
                             rt->bus->drop_count(true, PRIO_FILE),
                             rt->bus->drop_count(true, PRIO_CTRL),
                             rt->bus->drop_count(false, PRIO_NETWORK),
                             rt->bus->drop_count(false, PRIO_DNS),
                             total);
                last_drop_total = total;
            }
            last_drop = now;
        }

        // 用户态计数器的周期同步在主循环做（本线程内层 pop 循环在高压下
        // 不退出，周期任务会被饿死）；此处只保留退出后的最终同步。

        // tombstone sweep：每 60s；顺带 malloc_trim 归还压测峰值后
        // glibc arena 持有的空闲堆页（R13 内存收敛，best effort）
        if (now - last_sweep >= 60000000000ULL) {
            rt->tree->sweep_tombstones();
            malloc_trim(0);
            last_sweep = now;
        }

        // 告警 retention：每 3600s（自消费线程执行，避免与文件处理并发）
        if (now - last_retention >= 3600000000000ULL) {
            if (rt->alert_mgr)
                rt->alert_mgr->RunRetention();
            last_retention = now;
        }

        if (!did_work) {
            struct timespec ts {0, idle_backoff_ns};   // 空闲退避（自适应 200us~2ms）
            nanosleep(&ts, nullptr);
            if (idle_backoff_ns < 2000000)
                idle_backoff_ns *= 2;
        }
    }

    // 退出前 drain 残余事件并落库收尾
    EventRecord rec;
    while (rt->bus->try_pop_hi(rec))
        route_event_guarded(rec, rt);
    while (rt->bus->try_pop_lo(rec))
        route_event_guarded(rec, rt);
    if (rt->store)
        rt->store->Flush();
    // drain + 落库收尾后最终同步一次计数器（对账读取的最终状态）
    sync_user_stats(rt->user_stats_fd, rt->bus, rt->store, rt->mctx);
}
