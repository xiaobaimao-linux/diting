#pragma once

#include <sqlite3.h>

#include <string>
#include <vector>

namespace cis {

struct CisResultRow {
    int64_t id = 0;
    std::string check_id;
    std::string category;
    std::string description;
    std::string severity;
    std::string compliance;
    std::string result;
    std::string expected;
    std::string actual;
    std::string reason;
    std::string checked_at;
    std::string host;
};

class CisStore {
public:
    explicit CisStore(const std::string& db_path);  // 打开/建表失败抛 std::runtime_error
    ~CisStore();

    CisStore(const CisStore&) = delete;
    CisStore& operator=(const CisStore&) = delete;

    bool SaveResult(const CisResultRow& row);

    // 每个 check_id 取最新一行；filter 为空串表示不过滤
    std::vector<CisResultRow> GetLatest(const std::string& severity_filter,
                                        const std::string& result_filter);

private:
    sqlite3* db_ = nullptr;
};

} // namespace cis
