#include "notify_dispatcher.hpp"
#include "notify_router.hpp"
#include "syslog_notifier.hpp"
#include "webhook_notifier.hpp"
#include <spdlog/spdlog.h>

NotifyDispatcher::NotifyDispatcher() {
    worker_ = std::thread(&NotifyDispatcher::WorkerMain, this);
}

void NotifyDispatcher::Shutdown() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        stop_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

NotifyDispatcher::~NotifyDispatcher() {
    Shutdown();
}

void NotifyDispatcher::UpdateConfig(const NotifyConfig& cfg) {
    std::lock_guard<std::mutex> lk(mu_);
    const bool url_changed = (cfg.webhook_url != cfg_.webhook_url);
    const bool syslog_changed = (cfg.syslog.enabled != cfg_.syslog.enabled ||
                                 cfg.syslog.host != cfg_.syslog.host ||
                                 cfg.syslog.port != cfg_.syslog.port);
    const bool agg_turned_off = (cfg_.aggregation_window_minutes > 0 &&
                                 cfg.aggregation_window_minutes <= 0);
    cfg_ = cfg;
    if (url_changed) {
        // 渠道对象随 url 整体换新（工作线程持 shared_ptr 快照，发送中途换 url 安全）
        notifier_.reset();
        if (!cfg_.webhook_url.empty()) {
            notifier_ = std::make_shared<WebhookNotifier>(cfg_.webhook_url);
        }
    }
    if (syslog_changed) {
        // syslog 渠道对象随开关/host/port 整体换新（同 webhook 快照口径）
        syslog_notifier_.reset();
        if (cfg_.syslog.enabled) {
            syslog_notifier_ = std::make_shared<SyslogNotifier>(cfg_.syslog.host,
                                                                cfg_.syslog.port);
        }
    }
    // 聚合被关闭时把残余窗口全部结算，避免合并计数永远等不到摘要
    if (agg_turned_off) {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = agg_windows_.begin(); it != agg_windows_.end();) {
            FlushAggWindowLocked(it, now);
            it = agg_windows_.erase(it);
        }
    }
    cv_.notify_one();   // 窗口时长热更新后，工作线程需重算到期点
}

// 静默判定 + 入队（要求持有 mu_）。开窗首条与聚合摘要共用同一出口，
// suppressed/dropped 计数口径与 W5 D4 一致
void NotifyDispatcher::EnqueueWithSilence(const AlertEvent& evt,
                                          std::chrono::steady_clock::time_point now) {
    if (cfg_.silence_minutes > 0) {
        const std::string key = evt.rule_id + "|" + notify::SilenceObjectKey(evt);
        auto it = last_sent_.find(key);
        if (it != last_sent_.end() &&
            notify::SilenceWindowActive(it->second, now, cfg_.silence_minutes * 60)) {
            ++suppressed_;
            spdlog::debug("[notify] silenced: rule={} key={}", evt.rule_id, key);
            return;
        }
        // 仅在成功入队后才占用窗口槽位
        if (queue_.size() >= kMaxQueue) {
            ++dropped_;
            spdlog::warn("[notify] queue full ({}), alert dropped: rule={}",
                         kMaxQueue, evt.rule_id);
            return;
        }
        last_sent_[key] = now;
        if (last_sent_.size() > 4096) {   // 有界防膨胀（同祖先链缓存口径）
            last_sent_.clear();
            last_sent_[key] = now;
        }
        queue_.push(evt);
    } else {
        if (queue_.size() >= kMaxQueue) {
            ++dropped_;
            spdlog::warn("[notify] queue full ({}), alert dropped: rule={}",
                         kMaxQueue, evt.rule_id);
            return;
        }
        queue_.push(evt);
    }
    cv_.notify_one();
}

// 结算一个聚合窗口（要求持有 mu_）：有合并则生成摘要走静默出口，随后调用方擦除窗口
void NotifyDispatcher::FlushAggWindowLocked(
        std::unordered_map<std::string, AggWindow>::iterator it,
        std::chrono::steady_clock::time_point now) {
    AggWindow& w = it->second;
    if (w.pending <= 0) {
        return;
    }
    AlertEvent digest = w.last_evt;   // 以末条为代表（最新上下文），首末时间另附
    digest.occurrences = w.pending;
    digest.first_seen  = w.first_evt.timestamp;
    digest.last_seen   = w.last_evt.timestamp;
    spdlog::info("[notify] agg flush: rule={} occurrences={} first={} last={}",
                 digest.rule_id, digest.occurrences, digest.first_seen, digest.last_seen);
    EnqueueWithSilence(digest, now);
}

void NotifyDispatcher::FlushExpiredAggLocked(std::chrono::steady_clock::time_point now) {
    if (cfg_.aggregation_window_minutes <= 0) {
        return;
    }
    const int win = cfg_.aggregation_window_minutes * 60;
    for (auto it = agg_windows_.begin(); it != agg_windows_.end();) {
        if (!notify::SilenceWindowActive(it->second.win_start, now, win)) {
            FlushAggWindowLocked(it, now);
            it = agg_windows_.erase(it);
        } else {
            ++it;
        }
    }
}

std::chrono::steady_clock::time_point NotifyDispatcher::NextAggFlushDeadlineLocked() const {
    using time_point = std::chrono::steady_clock::time_point;
    if (cfg_.aggregation_window_minutes <= 0 || agg_windows_.empty()) {
        return time_point::max();
    }
    const auto win = std::chrono::seconds(cfg_.aggregation_window_minutes * 60);
    // 所有窗口都参与（含 pending=0）：开窗后工作线程可能已按"无到期点"睡眠，
    // 窗内 merge 不再 notify，到期点必须提前挂上，否则摘要永远等不到 flush
    time_point earliest = time_point::max();
    for (const auto& kv : agg_windows_) {
        earliest = std::min(earliest, kv.second.win_start + win);
    }
    return earliest;
}

void NotifyDispatcher::Dispatch(const AlertEvent& evt) {
    std::lock_guard<std::mutex> lk(mu_);

    if (!cfg_.enabled || (!notifier_ && !syslog_notifier_)) {
        return;
    }

    // 级别路由：低于全部启用通道的 min_level 仅落库，不外发
    // （任一通道通过即进入静默/聚合/入队管线；最终投递由工作线程按各通道
    // 自己的 min_level 决定。路由判定见 notify_router.hpp 单测）
    const bool pass_webhook = notifier_ &&
        notify::ShouldRouteByLevel(evt.severity, cfg_.min_level);
    const bool pass_syslog = syslog_notifier_ &&
        notify::ShouldRouteByLevel(evt.severity, cfg_.syslog.min_level);
    if (!pass_webhook && !pass_syslog) {
        spdlog::debug("[notify] routed out by min_level={}/syslog={}: rule={} severity={}",
                      cfg_.min_level, cfg_.syslog.min_level, evt.rule_id, evt.severity);
        return;
    }

    const auto now = std::chrono::steady_clock::now();

    // 聚合降噪（W5 D5，静默之上）：同 (rule_id, 对象) 窗口内首条立即外发，
    // 重复并入窗口计 merged，窗末补发一条 occurrences=N 摘要；落库保持逐条
    if (cfg_.aggregation_window_minutes > 0) {
        const int win = cfg_.aggregation_window_minutes * 60;
        const std::string key = evt.rule_id + "|" + notify::SilenceObjectKey(evt);
        auto it = agg_windows_.find(key);
        const notify::AggAction action = notify::AggregationAction(
            it != agg_windows_.end(),
            it != agg_windows_.end() ? it->second.win_start : now,
            now, win);
        if (action == notify::AggAction::kMerge) {
            AggWindow& w = it->second;
            ++w.pending;
            if (w.pending == 1) {
                w.first_evt = evt;
            }
            w.last_evt = evt;
            ++merged_;
            spdlog::debug("[notify] agg merged: rule={} key={} pending={}",
                          evt.rule_id, key, w.pending);
            return;
        }
        if (action == notify::AggAction::kFlushAndSend) {
            FlushAggWindowLocked(it, now);
            agg_windows_.erase(it);
        }
        // kOpenAndSend / kFlushAndSend：本条开新窗并立即外发（首条不延迟）
        AggWindow w;
        w.win_start = now;
        agg_windows_[key] = std::move(w);
        if (agg_windows_.size() > 4096) {   // 有界防膨胀（同静默 map 口径）
            agg_windows_.clear();
            AggWindow fresh;
            fresh.win_start = now;
            agg_windows_[key] = std::move(fresh);
        }
        // 开窗即唤醒工作线程重算到期点：首条可能被静默（不入队不唤醒），
        // 否则新窗口的到期点挂不上，摘要会睡到下一次入队
        cv_.notify_one();
    }

    EnqueueWithSilence(evt, now);
}

NotifyStats NotifyDispatcher::Stats() const {
    NotifyStats s;
    s.sent       = sent_.load();
    s.failed     = failed_.load();
    s.suppressed = suppressed_.load();
    s.dropped    = dropped_.load();
    s.merged     = merged_.load();
    return s;
}

void NotifyDispatcher::WorkerMain() {
    while (true) {
        AlertEvent evt;
        ChannelSnapshot channels[2];
        {
            std::unique_lock<std::mutex> lk(mu_);
            // 先结算到期聚合窗口（可能向队列补摘要），再等队列/下一个到期点
            FlushExpiredAggLocked(std::chrono::steady_clock::now());
            while (!stop_ && queue_.empty()) {
                const auto deadline = NextAggFlushDeadlineLocked();
                if (deadline == std::chrono::steady_clock::time_point::max()) {
                    cv_.wait(lk);
                } else {
                    cv_.wait_until(lk, deadline);
                }
                FlushExpiredAggLocked(std::chrono::steady_clock::now());
            }
            if (stop_) {
                return;   // 停机即退出，残余队列与未到期窗口不再发送
            }
            evt = std::move(queue_.front());
            queue_.pop();
            channels[0] = {notifier_, cfg_.min_level};
            channels[1] = {syslog_notifier_, cfg_.syslog.min_level};
        }

        // 锁外逐通道发送：每通道按自己的 min_level 决定投递，首试 + 最多 2 次
        // 重试（间隔 200ms），耗尽计 failed；通道间独立 try/catch 兜底，
        // 一个通道抛异常不影响另一个通道与本线程存活。
        // sent/failed 按"通道 × 告警"发送尝试计（口径见头文件注释）
        for (const ChannelSnapshot& ch : channels) {
            if (!ch.notifier) {
                continue;
            }
            if (!notify::ShouldRouteByLevel(evt.severity, ch.min_level)) {
                continue;   // 入队由任一通道通过触发，投递只看本通道 min_level
            }
            bool ok = false;
            try {
                for (int attempt = 0; attempt <= kMaxRetries; ++attempt) {
                    if (attempt > 0) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(kRetryBackoffMs));
                    }
                    if (ch.notifier->Send(evt)) {
                        ok = true;
                        break;
                    }
                }
            } catch (const std::exception& ex) {
                spdlog::error("[notify] {} send threw exception: {}", ch.notifier->Name(),
                              ex.what());
            } catch (...) {
                spdlog::error("[notify] {} send threw unknown exception",
                              ch.notifier->Name());
            }
            if (ok) {
                ++sent_;
                spdlog::info("[notify] {} sent: rule={} severity={} file={}",
                             ch.notifier->Name(), evt.rule_id, evt.severity, evt.file_path);
            } else {
                ++failed_;
                spdlog::warn("[notify] {} failed after {} retries, give up: rule={}",
                             ch.notifier->Name(), kMaxRetries, evt.rule_id);
            }
        }
    }
}
