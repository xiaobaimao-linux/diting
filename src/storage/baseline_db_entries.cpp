#include "baseline_db.hpp"
#include "commonfun.hpp"

#include <spdlog/spdlog.h>

#include <sqlite3.h>
#include <string>
#include <vector>

// 删除基线条目：精确匹配 + 可选递归前缀匹配，并写入审计记录
int BaselineDB::DeleteBaselineEntries(const std::vector<std::string>& paths, bool recursive,
                                      const std::string& source_label) {
    if (paths.empty()) {
        return 0;
    }

    // 收集需要删除的条目（先读取再删除，以便写入审计记录）
    std::vector<SnapshotEntry> to_delete;

    // 构建 SQL：对每个路径精确匹配；recursive 时对目录路径额外加前缀匹配
    std::string sql = "SELECT file_path, file_type, hash, permission, uid, gid, owner, grp, "
                      "file_size, mtime FROM baseline_entries WHERE ";
    std::vector<std::string> conditions;
    for (const auto& path : paths) {
        if (recursive) {
            // 精确匹配 OR 前缀匹配（path/ 开头）
            conditions.push_back(
                "(file_path = '" + path + "' OR "
                "(file_path LIKE '" + path + "/%' ESCAPE '\\'))");
        } else {
            conditions.push_back("file_path = '" + path + "'");
        }
    }
    for (size_t i = 0; i < conditions.size(); ++i) {
        sql += conditions[i];
        if (i + 1 < conditions.size()) sql += " OR ";
    }
    sql += ";";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("DeleteBaselineEntries: prepare query failed: {}", sqlite3_errmsg(db_));
        return 0;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        SnapshotEntry entry;
        entry.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        entry.file_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        entry.hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        entry.permission = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        entry.uid = sqlite3_column_int64(stmt, 4);
        entry.gid = sqlite3_column_int64(stmt, 5);
        const auto* owner = sqlite3_column_text(stmt, 6);
        const auto* grp = sqlite3_column_text(stmt, 7);
        entry.owner = owner != nullptr ? reinterpret_cast<const char*>(owner) : "";
        entry.grp = grp != nullptr ? reinterpret_cast<const char*>(grp) : "";
        entry.file_size = sqlite3_column_int64(stmt, 8);
        entry.mtime = sqlite3_column_int64(stmt, 9);
        to_delete.push_back(std::move(entry));
    }
    sqlite3_finalize(stmt);

    if (to_delete.empty()) {
        return 0;
    }

    // 在事务中执行删除 + 写入审计记录
    char* err_msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("DeleteBaselineEntries: begin transaction failed: {}",
                      err_msg != nullptr ? err_msg : sqlite3_errmsg(db_));
        sqlite3_free(err_msg);
        return 0;
    }

    // 审计插入语句
    const char* audit_sql = R"SQL(
        INSERT INTO baseline_audit (
            snapshot_id, label, file_path, change_type,
            old_file_type, old_hash, old_permission, old_uid, old_gid, old_owner, old_grp,
            old_file_size, old_mtime,
            new_file_type, new_hash, new_permission, new_uid, new_gid,
            new_owner, new_grp, new_file_size, new_mtime,
            changed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?);
    )SQL";
    sqlite3_stmt* audit_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, audit_sql, -1, &audit_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("DeleteBaselineEntries: prepare audit failed: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        return 0;
    }

    // 删除语句
    const char* delete_sql = "DELETE FROM baseline_entries WHERE file_path = ?;";
    sqlite3_stmt* delete_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, delete_sql, -1, &delete_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("DeleteBaselineEntries: prepare delete failed: {}", sqlite3_errmsg(db_));
        sqlite3_finalize(audit_stmt);
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        return 0;
    }

    const std::string now_str = NowIso();

    int deleted_count = 0;
    for (const auto& entry : to_delete) {
        // 写入审计记录
        sqlite3_reset(audit_stmt);
        sqlite3_clear_bindings(audit_stmt);
        int idx = 1;
        sqlite3_bind_text(audit_stmt, idx++, source_label.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(audit_stmt, idx++, source_label.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(audit_stmt, idx++, entry.file_path.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(audit_stmt, idx++, "delete", -1, SQLITE_STATIC);
        // old_* 字段
        sqlite3_bind_text(audit_stmt, idx++, entry.file_type.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(audit_stmt, idx++, entry.hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(audit_stmt, idx++, entry.permission.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(audit_stmt, idx++, entry.uid);
        sqlite3_bind_int64(audit_stmt, idx++, entry.gid);
        if (entry.owner.empty()) {
            sqlite3_bind_null(audit_stmt, idx++);
        } else {
            sqlite3_bind_text(audit_stmt, idx++, entry.owner.c_str(), -1, SQLITE_STATIC);
        }
        if (entry.grp.empty()) {
            sqlite3_bind_null(audit_stmt, idx++);
        } else {
            sqlite3_bind_text(audit_stmt, idx++, entry.grp.c_str(), -1, SQLITE_STATIC);
        }
        sqlite3_bind_int64(audit_stmt, idx++, entry.file_size);
        sqlite3_bind_int64(audit_stmt, idx++, entry.mtime);
        // new_* 全部为 NULL（已在 SQL 中硬编码）
        sqlite3_bind_text(audit_stmt, idx++, now_str.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(audit_stmt) != SQLITE_DONE) {
            spdlog::error("DeleteBaselineEntries: audit insert failed for {}: {}",
                          entry.file_path, sqlite3_errmsg(db_));
            sqlite3_finalize(audit_stmt);
            sqlite3_finalize(delete_stmt);
            sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
            return deleted_count;
        }

        // 删除基线条目
        sqlite3_reset(delete_stmt);
        sqlite3_clear_bindings(delete_stmt);
        sqlite3_bind_text(delete_stmt, 1, entry.file_path.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(delete_stmt) != SQLITE_DONE) {
            spdlog::error("DeleteBaselineEntries: delete failed for {}: {}",
                          entry.file_path, sqlite3_errmsg(db_));
            sqlite3_finalize(audit_stmt);
            sqlite3_finalize(delete_stmt);
            sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
            return deleted_count;
        }
        ++deleted_count;
    }

    sqlite3_finalize(audit_stmt);
    sqlite3_finalize(delete_stmt);

    if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("DeleteBaselineEntries: commit failed: {}",
                      err_msg != nullptr ? err_msg : sqlite3_errmsg(db_));
        sqlite3_free(err_msg);
        return 0;
    }

    return deleted_count;
}

// 分页查询 baseline_entries
ListResult BaselineDB::ListBaselineEntries(const std::string& path_filter,
                                            int limit,
                                            int offset) {
    ListResult result;

    // 1. 查询总数
    std::string count_sql = "SELECT COUNT(*) FROM baseline_entries";
    if (!path_filter.empty()) {
        count_sql += " WHERE file_path LIKE ?";
    }
    count_sql += ";";

    sqlite3_stmt* count_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, count_sql.c_str(), -1, &count_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("ListBaselineEntries: count prepare failed: {}", sqlite3_errmsg(db_));
        return result;
    }
    if (!path_filter.empty()) {
        sqlite3_bind_text(count_stmt, 1, path_filter.c_str(), -1, SQLITE_STATIC);
    }
    if (sqlite3_step(count_stmt) == SQLITE_ROW) {
        result.total_count = sqlite3_column_int64(count_stmt, 0);
    }
    sqlite3_finalize(count_stmt);

    if (result.total_count == 0) {
        return result;
    }

    // 2. 查询当前页数据
    std::string sql = "SELECT file_path, file_type, hash, permission, uid, gid, owner, grp, "
                      "file_size, mtime, snapshot_id, label, recorded_at "
                      "FROM baseline_entries";
    if (!path_filter.empty()) {
        sql += " WHERE file_path LIKE ?";
    }
    sql += " ORDER BY file_path";
    if (limit > 0) {
        sql += " LIMIT ?";
    }
    if (offset > 0) {
        sql += " OFFSET ?";
    }
    sql += ";";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("ListBaselineEntries: query prepare failed: {}", sqlite3_errmsg(db_));
        return result;
    }

    int param_idx = 1;
    if (!path_filter.empty()) {
        sqlite3_bind_text(stmt, param_idx++, path_filter.c_str(), -1, SQLITE_STATIC);
    }
    if (limit > 0) {
        sqlite3_bind_int(stmt, param_idx++, limit);
    }
    if (offset > 0) {
        sqlite3_bind_int(stmt, param_idx++, offset);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ListEntry entry;
        entry.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        entry.file_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        entry.hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        entry.permission = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        entry.uid = sqlite3_column_int64(stmt, 4);
        entry.gid = sqlite3_column_int64(stmt, 5);
        const auto* owner = sqlite3_column_text(stmt, 6);
        const auto* grp = sqlite3_column_text(stmt, 7);
        entry.owner = owner != nullptr ? reinterpret_cast<const char*>(owner) : "";
        entry.grp = grp != nullptr ? reinterpret_cast<const char*>(grp) : "";
        entry.file_size = sqlite3_column_int64(stmt, 8);
        entry.mtime = sqlite3_column_int64(stmt, 9);
        entry.snapshot_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        entry.label = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        entry.recorded_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        result.entries.push_back(std::move(entry));
    }
    sqlite3_finalize(stmt);

    return result;
}

// 获取全部基线条目（含快照元信息）
std::vector<CheckEntry> BaselineDB::GetAllBaselineEntries() {
    std::vector<CheckEntry> results;
    const char* sql = "SELECT file_path, file_type, hash, permission, uid, gid, owner, grp, "
                      "file_size, mtime, snapshot_id, label, recorded_at "
                      "FROM baseline_entries ORDER BY file_path;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("GetAllBaselineEntries: prepare failed: {}", sqlite3_errmsg(db_));
        return results;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CheckEntry entry;
        entry.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        entry.file_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        entry.hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        entry.permission = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        entry.uid = sqlite3_column_int64(stmt, 4);
        entry.gid = sqlite3_column_int64(stmt, 5);
        const auto* owner = sqlite3_column_text(stmt, 6);
        const auto* grp = sqlite3_column_text(stmt, 7);
        entry.owner = owner != nullptr ? reinterpret_cast<const char*>(owner) : "";
        entry.grp = grp != nullptr ? reinterpret_cast<const char*>(grp) : "";
        entry.file_size = sqlite3_column_int64(stmt, 8);
        entry.mtime = sqlite3_column_int64(stmt, 9);
        entry.snapshot_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        entry.label = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        entry.recorded_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        results.push_back(std::move(entry));
    }
    sqlite3_finalize(stmt);
    return results;
}

// 查询单条基线条目（按 file_path 精确匹配 baseline_entries 表）
bool BaselineDB::GetBaselineEntry(const std::string& file_path, CheckEntry& out) {
    const char* sql = "SELECT file_path, file_type, hash, permission, uid, gid, "
                      "owner, grp, file_size, mtime, snapshot_id, label, recorded_at "
                      "FROM baseline_entries WHERE file_path = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("GetBaselineEntry: prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    sqlite3_bind_text(stmt, 1, file_path.c_str(), -1, SQLITE_STATIC);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out.file_path   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        out.file_type   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        out.hash        = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        out.permission  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        out.uid         = sqlite3_column_int64(stmt, 4);
        out.gid         = sqlite3_column_int64(stmt, 5);
        const auto* owner = sqlite3_column_text(stmt, 6);
        const auto* grp   = sqlite3_column_text(stmt, 7);
        out.owner       = owner != nullptr ? reinterpret_cast<const char*>(owner) : "";
        out.grp         = grp   != nullptr ? reinterpret_cast<const char*>(grp)   : "";
        out.file_size   = sqlite3_column_int64(stmt, 8);
        out.mtime       = sqlite3_column_int64(stmt, 9);
        out.snapshot_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        out.label       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        out.recorded_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        found = true;
    }
    sqlite3_finalize(stmt);
    return found;
}
