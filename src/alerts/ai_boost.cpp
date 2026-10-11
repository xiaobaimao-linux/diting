#include "ai_boost.hpp"

#include <cstdio>
#include <ctime>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "severity.hpp"

namespace ai_boost {

namespace {

// assets.last_seen 兼容三种存量格式：NowIso() 的 "%Y-%m-%dT%H:%M:%S"、
// SQLite datetime('now','localtime') 的 "%Y-%m-%d %H:%M:%S"、
// NowString() 的 "%Y%m%d-%H:%M:%S"（均为本地时间）。解析失败返回 false。
bool ParseLocalTime(const std::string& s, std::time_t& out) {
    std::tm tm = {};
    int n = 0;
    if (std::sscanf(s.c_str(), "%d-%d-%dT%d:%d:%d%n", &tm.tm_year, &tm.tm_mon,
                    &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &n) == 6 &&
        n == static_cast<int>(s.size())) {
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;
    } else if (std::sscanf(s.c_str(), "%d-%d-%d %d:%d:%d%n", &tm.tm_year, &tm.tm_mon,
                           &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &n) == 6 &&
               n == static_cast<int>(s.size())) {
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;
    } else if (std::sscanf(s.c_str(), "%4d%2d%2d-%d:%d:%d%n", &tm.tm_year, &tm.tm_mon,
                           &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &n) == 6 &&
               n == static_cast<int>(s.size())) {
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;
    } else {
        return false;
    }
    tm.tm_isdst = -1;
    out = std::mktime(&tm);
    return out != static_cast<std::time_t>(-1);
}

bool DetailJsonHasAiWorkload(const std::string& detail_json) {
    try {
        const auto j = nlohmann::json::parse(detail_json);
        return j.value("ai_workload", false);
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

BoostCache::BoostCache(BaselineDB* db, long stale_seconds, long cache_ttl_seconds)
    : db_(db), stale_seconds_(stale_seconds), cache_ttl_seconds_(cache_ttl_seconds) {}

bool BoostCache::IsFresh(const std::string& last_seen) const {
    std::time_t seen = 0;
    if (!ParseLocalTime(last_seen, seen)) {
        return false;  // 无法解析的时间串按过期处理（宁缺毋滥）
    }
    const std::time_t now = std::time(nullptr);
    if (seen >= now) {
        return true;  // 时钟偏差容忍：未来时间视为新鲜
    }
    return (now - seen) <= stale_seconds_;
}

bool BoostCache::Lookup(const std::string& cache_key, const std::string& asset_type,
                        const std::string& name, bool require_ai_flag) {
    const auto now = std::chrono::steady_clock::now();
    auto it = cache_.find(cache_key);
    if (it != cache_.end() &&
        std::chrono::duration_cast<std::chrono::seconds>(now - it->second.fetched_at)
                .count() < cache_ttl_seconds_) {
        return it->second.hit;
    }

    bool hit = false;
    AssetRecord rec;
    if (db_->GetAsset(asset_type, name, rec) && IsFresh(rec.last_seen)) {
        hit = require_ai_flag ? DetailJsonHasAiWorkload(rec.detail_json) : true;
    }
    cache_[cache_key] = CacheEntry{hit, now};
    return hit;
}

bool BoostCache::CheckProcess(const std::string& comm_pid) {
    return Lookup("p:" + comm_pid, "process", comm_pid, true);
}

bool BoostCache::CheckModelFile(const std::string& file_path) {
    return Lookup("f:" + file_path, "model_file", file_path, false);
}

void BoostCache::MaybeBoost(AlertEvent& evt) {
    if (db_ == nullptr) {
        return;
    }

    std::string reason;
    if (!evt.process_name.empty() && evt.pid > 0) {
        const std::string key = evt.process_name + "(" + std::to_string(evt.pid) + ")";
        if (CheckProcess(key)) {
            reason = kReasonProcessAiWorkload;
        }
    }
    if (!evt.file_path.empty() && CheckModelFile(evt.file_path)) {
        if (!reason.empty()) {
            reason += ',';
        }
        reason += kReasonModelFileTarget;
    }

    if (reason.empty()) {
        return;  // 未命中：severity_origin 留空、escalated=false
    }

    evt.severity_origin = evt.severity;
    evt.escalated = true;
    evt.escalation_reason = reason;

    alert::Severity sev;
    if (!alert::SeverityFromString(evt.severity, sev) ||
        sev == alert::Severity::Critical) {
        // critical 封顶（仍记录 severity_origin 与 reason）；非法级别不动
        spdlog::info("[ai_boost] hit ({}) rule={} pid={} severity={} (no upgrade)",
                     reason, evt.rule_id, evt.pid, evt.severity);
        return;
    }
    // 枚举序 Critical<High<Medium<Low，升一级即枚举值减一
    sev = static_cast<alert::Severity>(static_cast<int>(sev) - 1);
    evt.severity = alert::SeverityToString(sev);
    spdlog::info("[ai_boost] severity {} -> {} ({}) rule={} pid={}", evt.severity_origin,
                 evt.severity, reason, evt.rule_id, evt.pid);
}

}  // namespace ai_boost
