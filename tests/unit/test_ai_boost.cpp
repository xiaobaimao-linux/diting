// 单元测试：AI 告警升级（ai_boost::BoostCache，W6 D4）
// 用 /tmp 临时库 + UpsertAssets 造资产数据，断言级别映射/封顶/新鲜度/缓存行为。
// 编译见 tests/Makefile test_ai_boost

#include <cassert>
#include <cstdio>
#include <string>
#include <thread>
#include <chrono>

#include <sqlite3.h>

#include "ai_boost.hpp"
#include "baseline_db.hpp"

namespace {

constexpr const char* kDbPath = "/tmp/baseline_test_ai_boost.db";

void RemoveDb() {
    std::remove(kDbPath);
    std::remove((std::string(kDbPath) + "-wal").c_str());
    std::remove((std::string(kDbPath) + "-shm").c_str());
}

AssetRecord MakeProcessAsset(const std::string& name, bool ai_workload) {
    AssetRecord a;
    a.asset_type = "process";
    a.name = name;
    a.detail_json = ai_workload ? "{\"ai_workload\":true}" : "{\"ai_workload\":false}";
    return a;
}

AssetRecord MakeModelFileAsset(const std::string& path) {
    AssetRecord a;
    a.asset_type = "model_file";
    a.name = path;
    a.detail_json = "{\"size\":1024}";
    return a;
}

AlertEvent MakeEvent(const std::string& severity, const std::string& comm, int pid,
                     const std::string& file_path) {
    AlertEvent evt;
    evt.rule_id = "TEST-RULE";
    evt.severity = severity;
    evt.process_name = comm;
    evt.pid = pid;
    evt.file_path = file_path;
    return evt;
}

// 用独立 sqlite3 连接直接把 last_seen 改成过去时间（UpsertAssets 固定写 NowIso）
void BackdateLastSeen(const std::string& asset_type, const std::string& name,
                      const std::string& last_seen) {
    sqlite3* db = nullptr;
    assert(sqlite3_open(kDbPath, &db) == SQLITE_OK);
    std::string sql = "UPDATE assets SET last_seen = '" + last_seen +
                      "' WHERE asset_type = '" + asset_type + "' AND name = '" + name + "';";
    char* err = nullptr;
    assert(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) == SQLITE_OK);
    sqlite3_close(db);
}

// ====== AIB-001: AI 进程告警 high → critical ======
void test_process_ai_boost_high_to_critical() {
    RemoveDb();
    BaselineDB db(kDbPath);
    db.UpsertAssets({MakeProcessAsset("python3(4210)", true)});

    ai_boost::BoostCache cache(&db, 7200);
    auto evt = MakeEvent("high", "python3", 4210, "/etc/shadow");
    cache.MaybeBoost(evt);

    assert(evt.severity == "critical");
    assert(evt.escalated);
    assert(evt.severity_origin == "high");
    assert(evt.escalation_reason == "process_ai_workload");
}

// ====== AIB-002: critical 封顶（仍记 severity_origin 与 reason） ======
void test_critical_capped() {
    RemoveDb();
    BaselineDB db(kDbPath);
    db.UpsertAssets({MakeProcessAsset("python3(4210)", true)});

    ai_boost::BoostCache cache(&db, 7200);
    auto evt = MakeEvent("critical", "python3", 4210, "/etc/shadow");
    cache.MaybeBoost(evt);

    assert(evt.severity == "critical");
    assert(evt.escalated);
    assert(evt.severity_origin == "critical");
    assert(evt.escalation_reason == "process_ai_workload");
}

// ====== AIB-003: 非 AI 进程（无资产行 / ai_workload=false）不升级 ======
void test_non_ai_not_boosted() {
    RemoveDb();
    BaselineDB db(kDbPath);
    db.UpsertAssets({MakeProcessAsset("cat(4300)", false)});

    ai_boost::BoostCache cache(&db, 7200);

    // 有资产行但 ai_workload=false
    auto evt = MakeEvent("high", "cat", 4300, "/etc/shadow");
    cache.MaybeBoost(evt);
    assert(evt.severity == "high");
    assert(!evt.escalated);
    assert(evt.severity_origin.empty());
    assert(evt.escalation_reason.empty());

    // 完全无资产行
    evt = MakeEvent("high", "grep", 4301, "/etc/shadow");
    cache.MaybeBoost(evt);
    assert(evt.severity == "high");
    assert(!evt.escalated);
    assert(evt.severity_origin.empty());
}

// ====== AIB-004: 过期 last_seen 不升级 ======
void test_stale_mark_not_boosted() {
    RemoveDb();
    BaselineDB db(kDbPath);
    db.UpsertAssets({MakeProcessAsset("python3(4210)", true)});
    BackdateLastSeen("process", "python3(4210)", "2020-01-01T00:00:00");

    ai_boost::BoostCache cache(&db, 7200);
    auto evt = MakeEvent("high", "python3", 4210, "/etc/shadow");
    cache.MaybeBoost(evt);

    assert(evt.severity == "high");
    assert(!evt.escalated);
    assert(evt.severity_origin.empty());
}

// ====== AIB-005: model_file 资产命中升级（进程非 AI 也升） ======
void test_model_file_boost() {
    RemoveDb();
    BaselineDB db(kDbPath);
    db.UpsertAssets({MakeModelFileAsset("/data/model.pt")});

    ai_boost::BoostCache cache(&db, 7200);
    auto evt = MakeEvent("medium", "cat", 4300, "/data/model.pt");
    cache.MaybeBoost(evt);

    assert(evt.severity == "high");
    assert(evt.escalated);
    assert(evt.severity_origin == "medium");
    assert(evt.escalation_reason == "model_file_target");
}

// ====== AIB-006: 进程 + 模型文件双命中，reason 逗号连接、级别只升一级 ======
void test_double_hit_single_step() {
    RemoveDb();
    BaselineDB db(kDbPath);
    db.UpsertAssets({MakeProcessAsset("python3(4210)", true),
                     MakeModelFileAsset("/data/model.pt")});

    ai_boost::BoostCache cache(&db, 7200);
    auto evt = MakeEvent("low", "python3", 4210, "/data/model.pt");
    cache.MaybeBoost(evt);

    assert(evt.severity == "medium");  // 只升一级
    assert(evt.escalated);
    assert(evt.severity_origin == "low");
    assert(evt.escalation_reason == "process_ai_workload,model_file_target");
}

// ====== AIB-007: TTL 内缓存命中（含阴性），TTL 过期重查 ======
void test_cache_ttl() {
    RemoveDb();
    BaselineDB db(kDbPath);

    ai_boost::BoostCache cache(&db, 7200, /*cache_ttl_seconds=*/1);

    // 无资产 → 阴性结果被缓存：随后插入资产但 TTL 内仍不升级
    auto evt = MakeEvent("high", "python3", 4210, "/etc/shadow");
    cache.MaybeBoost(evt);
    assert(!evt.escalated);

    db.UpsertAssets({MakeProcessAsset("python3(4210)", true)});
    evt = MakeEvent("high", "python3", 4210, "/etc/shadow");
    cache.MaybeBoost(evt);
    assert(!evt.escalated);  // 阴性缓存仍生效

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    evt = MakeEvent("high", "python3", 4210, "/etc/shadow");
    cache.MaybeBoost(evt);
    assert(evt.severity == "critical");  // TTL 过期后重查命中
    assert(evt.escalated);
}

// ====== AIB-008: db 为空时 no-op ======
void test_null_db_noop() {
    ai_boost::BoostCache cache(nullptr, 7200);
    auto evt = MakeEvent("high", "python3", 4210, "/etc/shadow");
    cache.MaybeBoost(evt);
    assert(evt.severity == "high");
    assert(!evt.escalated);
}

}  // namespace

int main() {
    test_process_ai_boost_high_to_critical();
    test_critical_capped();
    test_non_ai_not_boosted();
    test_stale_mark_not_boosted();
    test_model_file_boost();
    test_double_hit_single_step();
    test_cache_ttl();
    test_null_db_noop();
    RemoveDb();
    std::printf("test_ai_boost: all 8 cases passed\n");
    return 0;
}
