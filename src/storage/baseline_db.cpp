#include "baseline_db.hpp"
#include "baseline_db_internal.hpp"

#include <spdlog/spdlog.h>

#include <sqlite3.h>
#include <filesystem>
#include <stdexcept>
#include <string>

// PRAGMA table_info 探测 alerts 表已有列
AlertsColumns ProbeAlertsColumns(sqlite3* db) {
    AlertsColumns cols;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(alerts);", -1, &stmt, nullptr) != SQLITE_OK)
        return cols;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* name = sqlite3_column_text(stmt, 1);
        if (name == nullptr)
            continue;
        const std::string col = reinterpret_cast<const char*>(name);
        if (col == "user_name")         cols.user_name = true;
        else if (col == "uid")          cols.uid = true;
        else if (col == "exe")          cols.exe = true;
        else if (col == "container_id") cols.container_id = true;
        else if (col == "ancestors")    cols.ancestors = true;
        else if (col == "attack")       cols.attack = true;
        else if (col == "severity_origin")    cols.severity_origin = true;
        else if (col == "escalated")          cols.escalated = true;
        else if (col == "escalation_reason")  cols.escalation_reason = true;
    }
    sqlite3_finalize(stmt);
    return cols;
}

// 组装 alerts 查询 SELECT 列表：既有 14 列顺序逐字节不变，进程上下文扩展列
// （exe/container_id/ancestors）追加在 recorded_at 之后；老库缺列补空串。
std::string BuildAlertsSelect(const AlertsColumns& cols) {
    std::string sql =
        "SELECT rule_id, rule_name, severity, file_path, event_type, process_name, pid, ";
    sql += (cols.user_name && cols.uid) ? "user_name, uid, " : "'' AS user_name, '' AS uid, ";
    sql += "expected, actual, action_taken, dingtalk_sent, recorded_at, ";
    sql += cols.exe ? "exe, " : "'' AS exe, ";
    sql += cols.container_id ? "container_id, " : "'' AS container_id, ";
    sql += cols.ancestors ? "ancestors, " : "'' AS ancestors, ";
    sql += cols.attack ? "attack" : "'' AS attack";
    sql += cols.severity_origin ? ", severity_origin" : ", '' AS severity_origin";
    sql += cols.escalated ? ", escalated" : ", 0 AS escalated";
    sql += cols.escalation_reason ? ", escalation_reason" : ", '' AS escalation_reason";
    return sql;
}

BaselineDB::BaselineDB(const std::string &db_path) {
    const std::filesystem::path path(db_path);
    if (path.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            throw std::runtime_error("Failed to create database directory: " + ec.message());
        }
    }

    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
        throw std::runtime_error("Failed to open database: " + std::string(sqlite3_errmsg(db_)));
    }

    setWAL();
    InitTable();
}

void BaselineDB::setWAL() {
    const char *sql_wal = "PRAGMA journal_mode=WAL;";
    char *err_msg = nullptr;
    const int rc = sqlite3_exec(db_, sql_wal, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::debug("set sqlite WAL failed: {}", err_msg != nullptr ? err_msg : sqlite3_errmsg(db_));
    }
    sqlite3_free(err_msg);
}

BaselineDB::~BaselineDB() {
    sqlite3_close(db_);
}

void BaselineDB::InitTable() {
    const char *sql = R"SQL(
        CREATE TABLE IF NOT EXISTS baselines (
            file_path TEXT PRIMARY KEY,
            hash TEXT,
            permission TEXT,
            owner TEXT,
            grp TEXT,
            recorded_at TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            rule_name TEXT,
            severity TEXT,
            file_path TEXT NOT NULL,
            event_type TEXT,
            process_name TEXT,
            pid INTEGER,
            user_name TEXT,
            uid TEXT,
            expected TEXT,
            actual TEXT,
            action_taken TEXT,
            dingtalk_sent INTEGER DEFAULT 0,
            recorded_at TEXT NOT NULL,
            severity_origin TEXT DEFAULT '',
            escalated INTEGER DEFAULT 0,
            escalation_reason TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(recorded_at);
        CREATE TABLE IF NOT EXISTS baseline_entries (
            file_path TEXT PRIMARY KEY,
            file_type TEXT NOT NULL DEFAULT 'regular',
            hash TEXT NOT NULL,
            permission TEXT NOT NULL,
            uid INTEGER NOT NULL DEFAULT 0,
            gid INTEGER NOT NULL DEFAULT 0,
            owner TEXT,
            grp TEXT,
            file_size INTEGER NOT NULL DEFAULT 0,
            mtime INTEGER NOT NULL DEFAULT 0,
            snapshot_id TEXT NOT NULL,
            label TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS baseline_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            status TEXT NOT NULL,
            roots TEXT NOT NULL,
            excludes TEXT NOT NULL,
            recursive INTEGER NOT NULL,
            scanned_count INTEGER NOT NULL DEFAULT 0,
            added_count INTEGER NOT NULL DEFAULT 0,
            modified_count INTEGER NOT NULL DEFAULT 0,
            removed_count INTEGER NOT NULL DEFAULT 0,
            unchanged_count INTEGER NOT NULL DEFAULT 0,
            error_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS baseline_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            label TEXT NOT NULL,
            file_path TEXT NOT NULL,
            change_type TEXT NOT NULL,
            old_file_type TEXT,
            old_hash TEXT,
            old_permission TEXT,
            old_uid INTEGER,
            old_gid INTEGER,
            old_owner TEXT,
            old_grp TEXT,
            old_file_size INTEGER,
            old_mtime INTEGER,
            new_file_type TEXT,
            new_hash TEXT,
            new_permission TEXT,
            new_uid INTEGER,
            new_gid INTEGER,
            new_owner TEXT,
            new_grp TEXT,
            new_file_size INTEGER,
            new_mtime INTEGER,
            changed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_baseline_audit_path_time
            ON baseline_audit(file_path, changed_at);
        CREATE INDEX IF NOT EXISTS idx_baseline_audit_snapshot
            ON baseline_audit(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_baseline_snapshots_label
            ON baseline_snapshots(label, started_at);
    )SQL";
    char *err_msg = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        const std::string error = err_msg != nullptr ? err_msg : sqlite3_errmsg(db_);
        sqlite3_free(err_msg);
        throw std::runtime_error("Failed to initialize database: " + error);
    }

    // 兼容旧版 alerts 表：重复执行 ALTER TABLE 时忽略 duplicate column 错误。
    sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN user_name TEXT DEFAULT '';", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN uid TEXT DEFAULT '';", nullptr, nullptr, nullptr);

    // 进程上下文扩展列（M0-1）：PRAGMA table_info 探测，缺列才 ALTER 补加。
    // 老库首次打开即完成迁移；ALTER 失败（极端场景）由查询侧补空串兜底。
    const AlertsColumns alerts_cols = ProbeAlertsColumns(db_);
    if (!alerts_cols.exe)
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN exe TEXT;", nullptr, nullptr, nullptr);
    if (!alerts_cols.container_id)
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN container_id TEXT;", nullptr, nullptr, nullptr);
    if (!alerts_cols.ancestors)
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN ancestors TEXT;", nullptr, nullptr, nullptr);
    if (!alerts_cols.attack)
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN attack TEXT;", nullptr, nullptr, nullptr);
    // AI 升级列（W6 D4）：新库 CREATE TABLE 已含，老库按探测结果补加
    if (!alerts_cols.severity_origin)
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN severity_origin TEXT DEFAULT '';", nullptr, nullptr, nullptr);
    if (!alerts_cols.escalated)
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN escalated INTEGER DEFAULT 0;", nullptr, nullptr, nullptr);
    if (!alerts_cols.escalation_reason)
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN escalation_reason TEXT DEFAULT '';", nullptr, nullptr, nullptr);

    const char *copy_sql = R"SQL(
        INSERT OR IGNORE INTO baseline_entries
        (file_path, file_type, hash, permission, uid, gid, owner, grp,
         file_size, mtime, snapshot_id, label, recorded_at)
        SELECT file_path, 'regular', hash, permission,
               CASE WHEN owner GLOB '[0-9]*' THEN CAST(owner AS INTEGER) ELSE 0 END,
               CASE WHEN grp GLOB '[0-9]*' THEN CAST(grp AS INTEGER) ELSE 0 END,
               owner, grp, 0, 0, 'legacy-migration', 'default', recorded_at
        FROM baselines;
    )SQL";
    if (sqlite3_exec(db_, copy_sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        // 只读打开（如普通用户读 root 拥有的库）时迁移必然失败：降级为警告，
        // 读路径（report/alerts/list）继续可用；库后续以可写方式打开时迁移会补跑
        // （INSERT OR IGNORE 幂等）。不可视为致命错误，否则 CLI 直接 core dump。
        const std::string error = err_msg != nullptr ? err_msg : sqlite3_errmsg(db_);
        sqlite3_free(err_msg);
        spdlog::warn("[baseline_db] legacy baselines migration skipped: {}", error);
    }

    // M1-2 assets 表：独立执行。只读打开（非 root 打开 root 拥有的旧库）时
    // CREATE TABLE 需要写权限，降级为警告——读路径（alerts/report/asset list）
    // 继续可用；库后续以可写方式打开时自动补建（CREATE TABLE IF NOT EXISTS 幂等）。
    const char *assets_sql = R"SQL(
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_type TEXT NOT NULL,
            name TEXT NOT NULL,
            detail_json TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(asset_type, name)
        );
        CREATE INDEX IF NOT EXISTS idx_assets_type_name ON assets(asset_type, name);
    )SQL";
    if (sqlite3_exec(db_, assets_sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        const std::string error = err_msg != nullptr ? err_msg : sqlite3_errmsg(db_);
        sqlite3_free(err_msg);
        spdlog::warn("[baseline_db] assets table init skipped: {}", error);
    }
}
