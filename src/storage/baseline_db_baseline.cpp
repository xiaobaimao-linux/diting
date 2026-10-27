#include "baseline_db.hpp"

#include <spdlog/spdlog.h>

#include <sqlite3.h>
#include <string>
#include <vector>

// 保存或更新基线
void BaselineDB::SaveBaseline(const BaselineRecord &record) {
    const char *sql = R"(
            INSERT OR REPLACE INTO baselines
            (file_path, hash, permission, owner, grp, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?);
        )";

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    sqlite3_bind_text(stmt, 1, record.file_path.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, record.hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, record.permission.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, record.owner.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, record.grp.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, record.recorded_at.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        spdlog::error("Save baseline failed: {}", sqlite3_errmsg(db_));
    }
    sqlite3_finalize(stmt);
}

// 查询基线
BaselineRecord BaselineDB::GetBaseline(const std::string &file_path) {
    const char *sql = "SELECT * FROM baselines WHERE file_path = ?;";
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, file_path.c_str(), -1, SQLITE_STATIC);

    BaselineRecord record;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        record.file_path = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        record.hash = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        record.permission = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
        record.owner = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
        record.grp = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
        record.recorded_at = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
    }

    sqlite3_finalize(stmt);
    return record;
}

// 获取所有基线（用于报告生成）
std::vector<BaselineRecord> BaselineDB::GetAllBaselines() {
    const char *sql = "SELECT * FROM baselines ORDER BY file_path;";
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    std::vector<BaselineRecord> results;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        BaselineRecord r;
        r.file_path = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        r.hash = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        r.permission = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
        r.owner = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
        r.grp = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
        r.recorded_at = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
        results.push_back(r);
    }

    sqlite3_finalize(stmt);
    return results;
}
