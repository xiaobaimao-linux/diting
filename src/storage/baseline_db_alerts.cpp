#include "baseline_db.hpp"
#include "baseline_db_internal.hpp"

#include <spdlog/spdlog.h>

#include <sqlite3.h>
#include <string>
#include <vector>

// recorded_at 归一化表达式（兼容 "YYYYmmdd-HH:MM:SS" 与 ISO 两种存量格式），
// GetMonitorEvents / GetAlertStats 的时间边界比较共用
#define BG_ALERTS_NORMALIZED_TIME                                                     \
    "CASE WHEN length(recorded_at) >= 17 AND substr(recorded_at, 5, 1) != '-' THEN"   \
    " substr(recorded_at, 1, 4) || '-' || substr(recorded_at, 5, 2) || '-' ||"        \
    " substr(recorded_at, 7, 2) || ' ' || substr(recorded_at, 10, 2) || ':' ||"       \
    " substr(recorded_at, 13, 2) || ':' || substr(recorded_at, 16, 2)"                \
    " ELSE replace(substr(recorded_at, 1, 19), 'T', ' ') END"

// 保存告警记录
void BaselineDB::SaveAlert(const AlertRecord &record) {
    const char *sql = R"(
            INSERT INTO alerts
            (rule_id, rule_name, severity, file_path, event_type,
             process_name, pid, user_name, uid, expected, actual, action_taken,
             dingtalk_sent, recorded_at, exe, container_id, ancestors, attack,
             severity_origin, escalated, escalation_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        )";

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    sqlite3_bind_text(stmt, 1, record.rule_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, record.rule_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, record.severity.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, record.file_path.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, record.event_type.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, record.process_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, record.pid);
    sqlite3_bind_text(stmt, 8, record.user_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, record.uid.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, record.expected.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 11, record.actual.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 12, record.action_taken.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 13, record.dingtalk_sent ? 1 : 0);
    sqlite3_bind_text(stmt, 14, record.recorded_at.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 15, record.exe.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 16, record.container_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 17, record.ancestors.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 18, record.attack.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 19, record.severity_origin.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 20, record.escalated ? 1 : 0);
    sqlite3_bind_text(stmt, 21, record.escalation_reason.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        spdlog::error("Save alert failed: {}", sqlite3_errmsg(db_));
    } else {
        spdlog::info("[DB] Alert saved: {} | {} | {}", record.rule_id, record.file_path,
                     record.recorded_at);
    }
    sqlite3_finalize(stmt);
}

// === Retention: 按天数清理 ===
// 返回删除的记录数
int BaselineDB::PurgeAlertsByAge(int retention_days) {
    if (retention_days <= 0) {
        return 0; // 永久保留
    }

    const char *sql = R"(
            DELETE FROM alerts
            WHERE recorded_at < datetime('now', '-' || ? || ' days');
        )";

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, retention_days);

    int deleted = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        deleted = sqlite3_changes(db_);
    }
    sqlite3_finalize(stmt);
    return deleted;
}

// === Retention: 按数量上限清理（保留最新的N条）===
// 返回删除的记录数
int BaselineDB::PurgeAlertsByCount(int max_records) {
    if (max_records <= 0) {
        return 0; // 不限制
    }

    const char *sql = R"(
            DELETE FROM alerts
            WHERE id NOT IN (
                SELECT id FROM alerts
                ORDER BY recorded_at DESC
                LIMIT ?
            );
        )";

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, max_records);

    int deleted = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        deleted = sqlite3_changes(db_);
    }
    sqlite3_finalize(stmt);
    return deleted;
}

// === 回收数据库空间（VACUUM）===
void BaselineDB::Vacuum() {
    sqlite3_exec(db_, "VACUUM;", nullptr, nullptr, nullptr);
}

// === 获取当前告警总数 ===
int BaselineDB::GetAlertCount() {
    const char *sql = "SELECT COUNT(*) FROM alerts;";
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

// 辅助函数：从 sqlite3_stmt 读取一行 AlertRecord（前 14 列为既有字段，
// 顺序逐字节不变；第 15~17 列为进程上下文扩展，老库查询补空串时按列数跳过）
static AlertRecord ReadAlertRecord(sqlite3_stmt* stmt) {
    AlertRecord r;
    r.rule_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    r.rule_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    r.severity = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    r.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    r.event_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
    r.process_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
    r.pid = sqlite3_column_int(stmt, 6);
    r.user_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
    r.uid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
    r.expected = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
    r.actual = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
    r.action_taken = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
    r.dingtalk_sent = sqlite3_column_int(stmt, 12) != 0;
    r.recorded_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13));
    // 进程上下文扩展列（NULL 视为空串）
    const int ncols = sqlite3_column_count(stmt);
    if (ncols > 14) {
        const auto* exe = sqlite3_column_text(stmt, 14);
        if (exe != nullptr)
            r.exe = reinterpret_cast<const char*>(exe);
    }
    if (ncols > 15) {
        const auto* cid = sqlite3_column_text(stmt, 15);
        if (cid != nullptr)
            r.container_id = reinterpret_cast<const char*>(cid);
    }
    if (ncols > 16) {
        const auto* anc = sqlite3_column_text(stmt, 16);
        if (anc != nullptr)
            r.ancestors = reinterpret_cast<const char*>(anc);
    }
    if (ncols > 17) {
        const auto* atk = sqlite3_column_text(stmt, 17);
        if (atk != nullptr)
            r.attack = reinterpret_cast<const char*>(atk);
    }
    // AI 升级列（W6 D4，NULL 视为空串/0）
    if (ncols > 18) {
        const auto* so = sqlite3_column_text(stmt, 18);
        if (so != nullptr)
            r.severity_origin = reinterpret_cast<const char*>(so);
    }
    if (ncols > 19) {
        r.escalated = sqlite3_column_int(stmt, 19) != 0;
    }
    if (ncols > 20) {
        const auto* er = sqlite3_column_text(stmt, 20);
        if (er != nullptr)
            r.escalation_reason = reinterpret_cast<const char*>(er);
    }
    return r;
}

// 查询告警记录：支持 rule 过滤、severity 过滤、今日过滤、数量限制
std::vector<AlertRecord> BaselineDB::GetAlerts(const std::string &rule_filter,
                                               const std::string &severity_filter, int limit,
                                               bool today) {
    const AlertsColumns cols = ProbeAlertsColumns(db_);
    std::string sql = BuildAlertsSelect(cols) + " FROM alerts";

    std::vector<std::string> conds;
    if (!rule_filter.empty()) {
        conds.push_back("(rule_id = ? OR rule_name = ?)");
    }
    if (!severity_filter.empty()) {
        conds.push_back("severity = ?");
    }
    if (today) {
        conds.push_back("date(recorded_at) = date('now')");
    }
    if (!conds.empty()) {
        sql += " WHERE ";
        for (size_t i = 0; i < conds.size(); ++i) {
            if (i > 0) {
                sql += " AND ";
            }
            sql += conds[i];
        }
    }

    sql += " ORDER BY recorded_at DESC LIMIT ?;";

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);

    int param_idx = 1;
    if (!rule_filter.empty()) {
        sqlite3_bind_text(stmt, param_idx++, rule_filter.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, param_idx++, rule_filter.c_str(), -1, SQLITE_STATIC);
    }
    if (!severity_filter.empty()) {
        sqlite3_bind_text(stmt, param_idx++, severity_filter.c_str(), -1, SQLITE_STATIC);
    }
    sqlite3_bind_int(stmt, param_idx, limit);

    std::vector<AlertRecord> results;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(ReadAlertRecord(stmt));
    }

    sqlite3_finalize(stmt);
    return results;
}

// 分级统计：severity × rule_id 聚合计数；since_cutoff 为归一化时间下限
// （"YYYY-MM-DD HH:MM:SS"，空串 = 全部时间），与 GetMonitorEvents 同一比较口径
std::vector<AlertStatRow> BaselineDB::GetAlertStats(const std::string &since_cutoff,
                                                    const std::string &severity_filter) {
    const std::string normalized_time = BG_ALERTS_NORMALIZED_TIME;
    std::string sql = "SELECT severity, rule_id, COUNT(*) FROM alerts";

    std::vector<std::string> conds;
    if (!since_cutoff.empty()) {
        conds.push_back("(" + normalized_time + ") >= ?");
    }
    if (!severity_filter.empty()) {
        conds.push_back("severity = ?");
    }
    if (!conds.empty()) {
        sql += " WHERE ";
        for (size_t i = 0; i < conds.size(); ++i) {
            if (i > 0) {
                sql += " AND ";
            }
            sql += conds[i];
        }
    }
    // 级别序 critical→low 固定，同级按计数降序、rule_id 字典序兜底
    sql += " GROUP BY severity, rule_id ORDER BY CASE severity WHEN 'critical' THEN 0 "
           "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, "
           "COUNT(*) DESC, rule_id;";

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("Prepare alert stats query failed: {}", sqlite3_errmsg(db_));
        return {};
    }

    int param_idx = 1;
    if (!since_cutoff.empty()) {
        sqlite3_bind_text(stmt, param_idx++, since_cutoff.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (!severity_filter.empty()) {
        sqlite3_bind_text(stmt, param_idx++, severity_filter.c_str(), -1, SQLITE_TRANSIENT);
    }

    std::vector<AlertStatRow> rows;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AlertStatRow row;
        const auto *sev = sqlite3_column_text(stmt, 0);
        const auto *rid = sqlite3_column_text(stmt, 1);
        row.severity = sev != nullptr ? reinterpret_cast<const char *>(sev) : "";
        row.rule_id = rid != nullptr ? reinterpret_cast<const char *>(rid) : "";
        row.count = sqlite3_column_int64(stmt, 2);
        rows.push_back(row);
    }
    sqlite3_finalize(stmt);
    return rows;
}

std::vector<AlertRecord> BaselineDB::GetMonitorEvents(const std::string& start,
                                                       const std::string& end) {
    const std::string normalized_time = BG_ALERTS_NORMALIZED_TIME;

    std::string sql = BuildAlertsSelect(ProbeAlertsColumns(db_)) + " FROM alerts";
    if (!start.empty() || !end.empty()) {
        sql += " WHERE ";
        if (!start.empty()) {
            sql += "(" + normalized_time + ") >= ?";
        }
        if (!start.empty() && !end.empty()) {
            sql += " AND ";
        }
        if (!end.empty()) {
            sql += "(" + normalized_time + ") <= ?";
        }
    }
    sql += " ORDER BY (" + normalized_time + ") DESC, id DESC;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("Prepare monitor event query failed: {}", sqlite3_errmsg(db_));
        return {};
    }

    int param_idx = 1;
    if (!start.empty()) {
        sqlite3_bind_text(stmt, param_idx++, start.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (!end.empty()) {
        sqlite3_bind_text(stmt, param_idx++, end.c_str(), -1, SQLITE_TRANSIENT);
    }

    std::vector<AlertRecord> results;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(ReadAlertRecord(stmt));
    }
    sqlite3_finalize(stmt);
    return results;
}
