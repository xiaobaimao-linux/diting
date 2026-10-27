#include "baseline_db.hpp"

#include <sqlite3.h>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

bool BaselineDB::ApplySnapshot(const std::string& snapshot_id,
                               const std::string& label,
                               const std::vector<SnapshotEntry>& entries,
                               const std::vector<SnapshotScope>& scopes,
                               const std::vector<std::string>& excludes,
                               bool recursive,
                               const std::string& roots_text,
                               const std::string& excludes_text,
                               const std::string& started_at,
                               const std::string& finished_at,
                               SnapshotStats& stats,
                               std::string& error) {
    auto exec = [&](const char* sql) {
        char* err_msg = nullptr;
        const int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            error = err_msg != nullptr ? err_msg : sqlite3_errmsg(db_);
            sqlite3_free(err_msg);
            return false;
        }
        return true;
    };
    auto rollback = [&]() {
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
    };
    auto bind_text = [](sqlite3_stmt* stmt, int index, const std::string& value) {
        return sqlite3_bind_text(stmt, index, value.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK;
    };
    auto bind_nullable_text = [](sqlite3_stmt* stmt, int index, const std::string& value) {
        if (value.empty()) {
            return sqlite3_bind_null(stmt, index) == SQLITE_OK;
        }
        return sqlite3_bind_text(stmt, index, value.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK;
    };

    std::map<std::string, SnapshotEntry> current;
    sqlite3_stmt* read_stmt = nullptr;
    const char* read_sql =
        "SELECT file_path, file_type, hash, permission, uid, gid, owner, grp, file_size, mtime "
        "FROM baseline_entries;";
    if (sqlite3_prepare_v2(db_, read_sql, -1, &read_stmt, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(db_);
        return false;
    }
    while (sqlite3_step(read_stmt) == SQLITE_ROW) {
        SnapshotEntry entry;
        entry.file_path = reinterpret_cast<const char*>(sqlite3_column_text(read_stmt, 0));
        entry.file_type = reinterpret_cast<const char*>(sqlite3_column_text(read_stmt, 1));
        entry.hash = reinterpret_cast<const char*>(sqlite3_column_text(read_stmt, 2));
        entry.permission = reinterpret_cast<const char*>(sqlite3_column_text(read_stmt, 3));
        entry.uid = sqlite3_column_int64(read_stmt, 4);
        entry.gid = sqlite3_column_int64(read_stmt, 5);
        const auto* owner = sqlite3_column_text(read_stmt, 6);
        const auto* grp = sqlite3_column_text(read_stmt, 7);
        entry.owner = owner != nullptr ? reinterpret_cast<const char*>(owner) : "";
        entry.grp = grp != nullptr ? reinterpret_cast<const char*>(grp) : "";
        entry.file_size = sqlite3_column_int64(read_stmt, 8);
        entry.mtime = sqlite3_column_int64(read_stmt, 9);
        current.emplace(entry.file_path, std::move(entry));
    }
    sqlite3_finalize(read_stmt);

    std::map<std::string, SnapshotEntry> scanned;
    for (const auto& entry : entries) {
        scanned[entry.file_path] = entry;
    }

    const auto under = [](const std::string& path, const SnapshotScope& scope) {
        if (scope.exact_file) {
            return path == scope.path;
        }
        if (scope.path == path) {
            return true;
        }
        if (!scope.recursive) {
            return std::filesystem::path(path).parent_path().string() == scope.path;
        }
        return path.size() > scope.path.size() &&
               path.compare(0, scope.path.size(), scope.path) == 0 &&
               path[scope.path.size()] == '/';
    };
    const auto excluded = [&](const std::string& path) {
        for (const auto& exclude : excludes) {
            if (path == exclude ||
                (path.size() > exclude.size() && path.compare(0, exclude.size(), exclude) == 0 &&
                 path[exclude.size()] == '/')) {
                return true;
            }
        }
        return false;
    };
    const auto in_scope = [&](const std::string& path) {
        if (excluded(path)) {
            return false;
        }
        for (const auto& scope : scopes) {
            if (under(path, scope)) {
                return true;
            }
        }
        return false;
    };
    for (const auto& [path, old_entry] : current) {
        if (in_scope(path) && scanned.find(path) == scanned.end()) {
            ++stats.removed;
        }
    }

    if (!exec("BEGIN IMMEDIATE;")) {
        return false;
    }

    const char* audit_sql = R"SQL(
        INSERT INTO baseline_audit (
            snapshot_id, label, file_path, change_type,
            old_file_type, old_hash, old_permission, old_uid, old_gid, old_owner, old_grp,
            old_file_size, old_mtime, new_file_type, new_hash, new_permission, new_uid, new_gid,
            new_owner, new_grp, new_file_size, new_mtime, changed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )SQL";
    sqlite3_stmt* audit_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, audit_sql, -1, &audit_stmt, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(db_);
        rollback();
        return false;
    }

    const auto write_audit = [&](const std::string& type, const std::string& path,
                                const SnapshotEntry* old_entry, const SnapshotEntry* new_entry) {
        sqlite3_reset(audit_stmt);
        sqlite3_clear_bindings(audit_stmt);
        int index = 1;
        bool ok = bind_text(audit_stmt, index++, snapshot_id) && bind_text(audit_stmt, index++, label) &&
                  bind_text(audit_stmt, index++, path) && bind_text(audit_stmt, index++, type);
        const auto bind_old = [&](const SnapshotEntry* entry) {
            if (!entry) {
                for (int i = 0; i < 9; ++i) {
                    if (sqlite3_bind_null(audit_stmt, index++) != SQLITE_OK) return false;
                }
                return true;
            }
            return bind_text(audit_stmt, index++, entry->file_type) && bind_text(audit_stmt, index++, entry->hash) &&
                   bind_text(audit_stmt, index++, entry->permission) && sqlite3_bind_int64(audit_stmt, index++, entry->uid) == SQLITE_OK &&
                   sqlite3_bind_int64(audit_stmt, index++, entry->gid) == SQLITE_OK && bind_nullable_text(audit_stmt, index++, entry->owner) &&
                   bind_nullable_text(audit_stmt, index++, entry->grp) && sqlite3_bind_int64(audit_stmt, index++, entry->file_size) == SQLITE_OK &&
                   sqlite3_bind_int64(audit_stmt, index++, entry->mtime) == SQLITE_OK;
        };
        const auto bind_new = [&](const SnapshotEntry* entry) {
            return bind_old(entry);
        };
        ok = ok && bind_old(old_entry) && bind_new(new_entry) && bind_text(audit_stmt, index++, finished_at);
        if (!ok || sqlite3_step(audit_stmt) != SQLITE_DONE) {
            error = sqlite3_errmsg(db_);
            return false;
        }
        return true;
    };

    const char* upsert_sql = R"SQL(
        INSERT INTO baseline_entries
        (file_path, file_type, hash, permission, uid, gid, owner, grp, file_size, mtime,
         snapshot_id, label, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(file_path) DO UPDATE SET
            file_type=excluded.file_type, hash=excluded.hash, permission=excluded.permission,
            uid=excluded.uid, gid=excluded.gid, owner=excluded.owner, grp=excluded.grp,
            file_size=excluded.file_size, mtime=excluded.mtime, snapshot_id=excluded.snapshot_id,
            label=excluded.label, recorded_at=excluded.recorded_at;
    )SQL";
    sqlite3_stmt* upsert_stmt = nullptr;
    const char* delete_sql = "DELETE FROM baseline_entries WHERE file_path = ?;";
    sqlite3_stmt* delete_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, upsert_sql, -1, &upsert_stmt, nullptr) != SQLITE_OK ||
        sqlite3_prepare_v2(db_, delete_sql, -1, &delete_stmt, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(db_);
        sqlite3_finalize(upsert_stmt);
        sqlite3_finalize(delete_stmt);
        sqlite3_finalize(audit_stmt);
        rollback();
        return false;
    }

    const auto write_entry = [&](const SnapshotEntry& entry) {
        sqlite3_reset(upsert_stmt);
        sqlite3_clear_bindings(upsert_stmt);
        int i = 1;
        return bind_text(upsert_stmt, i++, entry.file_path) && bind_text(upsert_stmt, i++, entry.file_type) &&
               bind_text(upsert_stmt, i++, entry.hash) && bind_text(upsert_stmt, i++, entry.permission) &&
               sqlite3_bind_int64(upsert_stmt, i++, entry.uid) == SQLITE_OK && sqlite3_bind_int64(upsert_stmt, i++, entry.gid) == SQLITE_OK &&
               bind_nullable_text(upsert_stmt, i++, entry.owner) && bind_nullable_text(upsert_stmt, i++, entry.grp) &&
               sqlite3_bind_int64(upsert_stmt, i++, entry.file_size) == SQLITE_OK && sqlite3_bind_int64(upsert_stmt, i++, entry.mtime) == SQLITE_OK &&
               bind_text(upsert_stmt, i++, snapshot_id) && bind_text(upsert_stmt, i++, label) && bind_text(upsert_stmt, i++, finished_at) &&
               sqlite3_step(upsert_stmt) == SQLITE_DONE;
    };
    const auto delete_entry = [&](const std::string& path) {
        sqlite3_reset(delete_stmt);
        sqlite3_clear_bindings(delete_stmt);
        return bind_text(delete_stmt, 1, path) && sqlite3_step(delete_stmt) == SQLITE_DONE;
    };

    for (const auto& [path, entry] : scanned) {
        const auto old_it = current.find(path);
        const SnapshotEntry* old_entry = old_it == current.end() ? nullptr : &old_it->second;
        const bool changed = old_entry == nullptr || old_entry->file_type != entry.file_type ||
                             old_entry->hash != entry.hash || old_entry->permission != entry.permission ||
                             old_entry->uid != entry.uid || old_entry->gid != entry.gid ||
                             old_entry->owner != entry.owner || old_entry->grp != entry.grp ||
                             old_entry->file_size != entry.file_size || old_entry->mtime != entry.mtime;
        if (!changed) {
            ++stats.unchanged;
        } else {
            if (old_entry == nullptr) {
                ++stats.added;
            } else {
                ++stats.modified;
            }
            if (!write_audit(old_entry == nullptr ? "added" : "modified", path, old_entry, &entry) ||
                !write_entry(entry)) {
                error = sqlite3_errmsg(db_);
                sqlite3_finalize(upsert_stmt);
                sqlite3_finalize(delete_stmt);
                sqlite3_finalize(audit_stmt);
                rollback();
                return false;
            }
        }
    }
    for (const auto& [path, old_entry] : current) {
        if (in_scope(path) && scanned.find(path) == scanned.end()) {
            if (!write_audit("removed", path, &old_entry, nullptr) || !delete_entry(path)) {
                error = sqlite3_errmsg(db_);
                sqlite3_finalize(upsert_stmt);
                sqlite3_finalize(delete_stmt);
                sqlite3_finalize(audit_stmt);
                rollback();
                return false;
            }
        }
    }

    const char* snapshot_sql = R"SQL(
        INSERT INTO baseline_snapshots
        (snapshot_id, label, started_at, finished_at, status, roots, excludes, recursive,
         scanned_count, added_count, modified_count, removed_count, unchanged_count, error_count)
        VALUES (?, ?, ?, ?, 'success', ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )SQL";
    sqlite3_stmt* snapshot_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, snapshot_sql, -1, &snapshot_stmt, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(db_);
        sqlite3_finalize(upsert_stmt);
        sqlite3_finalize(delete_stmt);
        sqlite3_finalize(audit_stmt);
        rollback();
        return false;
    }
    int i = 1;
    const bool bound = bind_text(snapshot_stmt, i++, snapshot_id) && bind_text(snapshot_stmt, i++, label) &&
                       bind_text(snapshot_stmt, i++, started_at) && bind_text(snapshot_stmt, i++, finished_at) &&
                       bind_text(snapshot_stmt, i++, roots_text) && bind_text(snapshot_stmt, i++, excludes_text) &&
                       sqlite3_bind_int(snapshot_stmt, i++, recursive ? 1 : 0) == SQLITE_OK &&
                       sqlite3_bind_int64(snapshot_stmt, i++, stats.scanned) == SQLITE_OK &&
                       sqlite3_bind_int64(snapshot_stmt, i++, stats.added) == SQLITE_OK &&
                       sqlite3_bind_int64(snapshot_stmt, i++, stats.modified) == SQLITE_OK &&
                       sqlite3_bind_int64(snapshot_stmt, i++, stats.removed) == SQLITE_OK &&
                       sqlite3_bind_int64(snapshot_stmt, i++, stats.unchanged) == SQLITE_OK &&
                       sqlite3_bind_int64(snapshot_stmt, i++, stats.errors) == SQLITE_OK &&
                       sqlite3_step(snapshot_stmt) == SQLITE_DONE;
    if (!bound || !exec("COMMIT;")) {
        if (error.empty()) error = sqlite3_errmsg(db_);
        sqlite3_finalize(snapshot_stmt);
        sqlite3_finalize(upsert_stmt);
        sqlite3_finalize(delete_stmt);
        sqlite3_finalize(audit_stmt);
        rollback();
        return false;
    }
    sqlite3_finalize(snapshot_stmt);
    sqlite3_finalize(upsert_stmt);
    sqlite3_finalize(delete_stmt);
    sqlite3_finalize(audit_stmt);
    stats.scanned = static_cast<std::int64_t>(entries.size());
    return true;
}

std::vector<SnapshotEntry> BaselineDB::GetSnapshotEntries() {
    std::vector<SnapshotEntry> result;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT file_path, file_type, hash, permission, uid, gid, owner, grp, file_size, mtime FROM baseline_entries ORDER BY file_path;";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return result;
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
        result.push_back(std::move(entry));
    }
    sqlite3_finalize(stmt);
    return result;
}

int BaselineDB::GetBaselineAuditCount() {
    sqlite3_stmt* stmt = nullptr;
    int count = 0;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM baseline_audit;", -1, &stmt, nullptr) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}
