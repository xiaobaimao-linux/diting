#include "cis_store.hpp"

#include <stdexcept>

namespace cis {

namespace {

void BindText(sqlite3_stmt* stmt, int index, const std::string& value) {
    sqlite3_bind_text(stmt, index, value.c_str(), static_cast<int>(value.size()),
                      SQLITE_TRANSIENT);
}

std::string ColumnText(sqlite3_stmt* stmt, int index) {
    const unsigned char* text = sqlite3_column_text(stmt, index);
    return text ? reinterpret_cast<const char*>(text) : "";
}

} // namespace

CisStore::CisStore(const std::string& db_path) {
    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
        const std::string msg = db_ ? sqlite3_errmsg(db_) : "out of memory";
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        throw std::runtime_error("打开数据库失败: " + db_path + ": " + msg);
    }

    char* errmsg = nullptr;
    const char* ddl =
        "PRAGMA busy_timeout=5000;"
        "CREATE TABLE IF NOT EXISTS cis_results ("
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    check_id TEXT NOT NULL,"
        "    category TEXT NOT NULL,"
        "    description TEXT,"
        "    severity TEXT,"
        "    compliance TEXT,"
        "    result TEXT NOT NULL,"
        "    expected TEXT,"
        "    actual TEXT,"
        "    reason TEXT,"
        "    checked_at TEXT NOT NULL,"
        "    host TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_cis_results_check "
        "ON cis_results(check_id, checked_at);";
    if (sqlite3_exec(db_, ddl, nullptr, nullptr, &errmsg) != SQLITE_OK) {
        const std::string msg = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("初始化 cis_results 表失败: " + msg);
    }
}

CisStore::~CisStore() {
    if (db_) {
        sqlite3_close(db_);
    }
}

bool CisStore::SaveResult(const CisResultRow& row) {
    const char* sql =
        "INSERT INTO cis_results (check_id, category, description, severity, compliance,"
        " result, expected, actual, reason, checked_at, host)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    BindText(stmt, 1, row.check_id);
    BindText(stmt, 2, row.category);
    BindText(stmt, 3, row.description);
    BindText(stmt, 4, row.severity);
    BindText(stmt, 5, row.compliance);
    BindText(stmt, 6, row.result);
    BindText(stmt, 7, row.expected);
    BindText(stmt, 8, row.actual);
    BindText(stmt, 9, row.reason);
    BindText(stmt, 10, row.checked_at);
    BindText(stmt, 11, row.host);
    const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

std::vector<CisResultRow> CisStore::GetLatest(const std::string& severity_filter,
                                              const std::string& result_filter) {
    std::vector<CisResultRow> rows;
    std::string sql =
        "SELECT id, check_id, category, description, severity, compliance, result,"
        " expected, actual, reason, checked_at, host FROM cis_results"
        " WHERE id IN (SELECT MAX(id) FROM cis_results GROUP BY check_id)";
    if (!severity_filter.empty()) {
        sql += " AND severity = ?";
    }
    if (!result_filter.empty()) {
        sql += " AND result = ?";
    }
    sql += " ORDER BY check_id;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return rows;
    }
    int param = 1;
    if (!severity_filter.empty()) {
        BindText(stmt, param++, severity_filter);
    }
    if (!result_filter.empty()) {
        BindText(stmt, param++, result_filter);
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CisResultRow row;
        row.id = sqlite3_column_int64(stmt, 0);
        row.check_id = ColumnText(stmt, 1);
        row.category = ColumnText(stmt, 2);
        row.description = ColumnText(stmt, 3);
        row.severity = ColumnText(stmt, 4);
        row.compliance = ColumnText(stmt, 5);
        row.result = ColumnText(stmt, 6);
        row.expected = ColumnText(stmt, 7);
        row.actual = ColumnText(stmt, 8);
        row.reason = ColumnText(stmt, 9);
        row.checked_at = ColumnText(stmt, 10);
        row.host = ColumnText(stmt, 11);
        rows.push_back(row);
    }
    sqlite3_finalize(stmt);
    return rows;
}

} // namespace cis
