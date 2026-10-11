#pragma once

#include <chrono>
#include <string>
#include <unordered_map>

#include "alert_event.hpp"
#include "baseline_db.hpp"

// AI 告警升级（W6 D4，设计见 docs/ai-alert-escalation.md）：
// 规则命中后构建 AlertEvent 时，若触发进程是 AI 工作负载（assets 表 process
// 资产 ai_workload=true）或目标路径命中 model_file 资产，严重级别升一级
// （critical 封顶）。资产查询结果带 TTL 内存缓存，命中路径不反复查库。
namespace ai_boost {

// 升级原因取值（同时命中逗号连接，级别仍只升一级）
inline constexpr const char* kReasonProcessAiWorkload = "process_ai_workload";
inline constexpr const char* kReasonModelFileTarget = "model_file_target";

class BoostCache {
public:
    // db 为空时 MaybeBoost 为 no-op；stale_seconds：last_seen 超过该秒数视为
    // 标记失效不升级；cache_ttl_seconds：资产判定结果（含阴性）缓存时长。
    BoostCache(BaselineDB* db, long stale_seconds, long cache_ttl_seconds = 60);

    // 命中则在 evt 上升级级别并填 severity_origin/escalated/escalation_reason；
    // 未命中不改动任何字段。单线程使用（消费线程），无锁。
    void MaybeBoost(AlertEvent& evt);

    // 测试/调试用：当前缓存条目数
    size_t CacheSize() const { return cache_.size(); }

private:
    struct CacheEntry {
        bool hit = false;
        std::chrono::steady_clock::time_point fetched_at;
    };

    bool CheckProcess(const std::string& comm_pid);
    bool CheckModelFile(const std::string& file_path);
    bool Lookup(const std::string& cache_key, const std::string& asset_type,
                const std::string& name, bool require_ai_flag);
    bool IsFresh(const std::string& last_seen) const;

    BaselineDB* db_;
    long stale_seconds_;
    long cache_ttl_seconds_;
    std::unordered_map<std::string, CacheEntry> cache_;
};

}  // namespace ai_boost
