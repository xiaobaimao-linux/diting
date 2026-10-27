#include "baseline_db.hpp"
#include "commonfun.hpp"

#include <spdlog/spdlog.h>

#include <sqlite3.h>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// === M1-2 资产清点 ===

AssetUpsertResult BaselineDB::UpsertAssets(const std::vector<AssetRecord>& assets) {
    AssetUpsertResult result;
    if (assets.empty()) {
        return result;
    }

    const char* insert_sql =
        "INSERT OR IGNORE INTO assets (asset_type, name, detail_json, first_seen, "
        "last_seen) VALUES (?, ?, ?, ?, ?);";
    const char* update_sql =
        "UPDATE assets SET detail_json = ?, last_seen = ? WHERE asset_type = ? AND name = ?;";
    sqlite3_stmt* insert_stmt = nullptr;
    sqlite3_stmt* update_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, insert_sql, -1, &insert_stmt, nullptr) != SQLITE_OK ||
        sqlite3_prepare_v2(db_, update_sql, -1, &update_stmt, nullptr) != SQLITE_OK) {
        sqlite3_finalize(insert_stmt);
        sqlite3_finalize(update_stmt);
        throw std::runtime_error(std::string("UpsertAssets: prepare failed: ") +
                                 sqlite3_errmsg(db_));
    }

    char* err_msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE TRANSACTION;", nullptr, nullptr, &err_msg) !=
        SQLITE_OK) {
        const std::string error = err_msg != nullptr ? err_msg : sqlite3_errmsg(db_);
        sqlite3_free(err_msg);
        sqlite3_finalize(insert_stmt);
        sqlite3_finalize(update_stmt);
        throw std::runtime_error("UpsertAssets: begin transaction failed: " + error);
    }

    // 同批次内 (asset_type, name) 重复时保留首条（如端口 SO_REUSEPORT 场景）
    std::set<std::pair<std::string, std::string>> seen_in_batch;
    bool failed = false;
    std::string fail_reason;
    for (const auto& asset : assets) {
        const std::string now = NowIso();
        if (!seen_in_batch.emplace(asset.asset_type, asset.name).second) {
            continue;
        }
        sqlite3_bind_text(insert_stmt, 1, asset.asset_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt, 2, asset.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt, 3, asset.detail_json.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt, 4, now.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt, 5, now.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(insert_stmt) != SQLITE_DONE) {
            failed = true;
            fail_reason = sqlite3_errmsg(db_);
            break;
        }
        if (sqlite3_changes(db_) > 0) {
            ++result.inserted;
        } else {
            sqlite3_bind_text(update_stmt, 1, asset.detail_json.c_str(), -1,
                              SQLITE_TRANSIENT);
            sqlite3_bind_text(update_stmt, 2, now.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(update_stmt, 3, asset.asset_type.c_str(), -1,
                              SQLITE_TRANSIENT);
            sqlite3_bind_text(update_stmt, 4, asset.name.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(update_stmt) != SQLITE_DONE) {
                failed = true;
                fail_reason = sqlite3_errmsg(db_);
                break;
            }
            ++result.updated;
        }
        sqlite3_reset(insert_stmt);
        sqlite3_reset(update_stmt);
        sqlite3_clear_bindings(insert_stmt);
        sqlite3_clear_bindings(update_stmt);
    }

    if (failed) {
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
    } else if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        fail_reason = err_msg != nullptr ? err_msg : sqlite3_errmsg(db_);
        sqlite3_free(err_msg);
        failed = true;
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
    }
    sqlite3_finalize(insert_stmt);
    sqlite3_finalize(update_stmt);
    if (failed) {
        throw std::runtime_error("UpsertAssets: " + fail_reason);
    }
    return result;
}

// 按 (asset_type, name) 精确查询单条资产（W6 D4 AI 升级判定用）
bool BaselineDB::GetAsset(const std::string& asset_type, const std::string& name,
                          AssetRecord& out) {
    const char* sql =
        "SELECT id, asset_type, name, detail_json, first_seen, last_seen "
        "FROM assets WHERE asset_type = ? AND name = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("GetAsset: prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    sqlite3_bind_text(stmt, 1, asset_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_TRANSIENT);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out.id = sqlite3_column_int64(stmt, 0);
        const auto* col = sqlite3_column_text(stmt, 1);
        out.asset_type = col != nullptr ? reinterpret_cast<const char*>(col) : "";
        col = sqlite3_column_text(stmt, 2);
        out.name = col != nullptr ? reinterpret_cast<const char*>(col) : "";
        col = sqlite3_column_text(stmt, 3);
        out.detail_json = col != nullptr ? reinterpret_cast<const char*>(col) : "";
        col = sqlite3_column_text(stmt, 4);
        out.first_seen = col != nullptr ? reinterpret_cast<const char*>(col) : "";
        col = sqlite3_column_text(stmt, 5);
        out.last_seen = col != nullptr ? reinterpret_cast<const char*>(col) : "";
        found = true;
    }
    sqlite3_finalize(stmt);
    return found;
}

std::int64_t BaselineDB::CountAssets(const std::string& asset_type) {
    const char* sql = asset_type.empty() ? "SELECT COUNT(*) FROM assets;"
                                         : "SELECT COUNT(*) FROM assets WHERE asset_type = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("CountAssets: prepare failed: {}", sqlite3_errmsg(db_));
        return 0;
    }
    if (!asset_type.empty()) {
        sqlite3_bind_text(stmt, 1, asset_type.c_str(), -1, SQLITE_STATIC);
    }
    std::int64_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

std::vector<AssetRecord> BaselineDB::GetAssets(const std::string& asset_type,
                                               std::int64_t limit, std::int64_t offset) {
    std::string sql =
        "SELECT id, asset_type, name, detail_json, first_seen, last_seen FROM assets";
    if (!asset_type.empty()) {
        sql += " WHERE asset_type = ?";
    }
    sql += " ORDER BY asset_type, name, id";
    if (limit > 0) {
        sql += " LIMIT ?";
        if (offset > 0) {
            sql += " OFFSET ?";
        }
    }
    sql += ";";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("GetAssets: prepare failed: {}", sqlite3_errmsg(db_));
        return {};
    }
    int idx = 1;
    if (!asset_type.empty()) {
        sqlite3_bind_text(stmt, idx++, asset_type.c_str(), -1, SQLITE_STATIC);
    }
    if (limit > 0) {
        sqlite3_bind_int64(stmt, idx++, limit);
        if (offset > 0) {
            sqlite3_bind_int64(stmt, idx++, offset);
        }
    }
    std::vector<AssetRecord> records;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AssetRecord record;
        record.id = sqlite3_column_int64(stmt, 0);
        const auto* type = sqlite3_column_text(stmt, 1);
        const auto* name = sqlite3_column_text(stmt, 2);
        const auto* detail = sqlite3_column_text(stmt, 3);
        const auto* first = sqlite3_column_text(stmt, 4);
        const auto* last = sqlite3_column_text(stmt, 5);
        record.asset_type = type != nullptr ? reinterpret_cast<const char*>(type) : "";
        record.name = name != nullptr ? reinterpret_cast<const char*>(name) : "";
        record.detail_json = detail != nullptr ? reinterpret_cast<const char*>(detail) : "";
        record.first_seen = first != nullptr ? reinterpret_cast<const char*>(first) : "";
        record.last_seen = last != nullptr ? reinterpret_cast<const char*>(last) : "";
        records.push_back(std::move(record));
    }
    sqlite3_finalize(stmt);
    return records;
}
