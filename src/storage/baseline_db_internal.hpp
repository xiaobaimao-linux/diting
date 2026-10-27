#pragma once

// baseline_db 模块内部共享声明（baseline_db.cpp / baseline_db_alerts.cpp 拆分共用）。
// 仅供 src/storage/baseline_db*.cpp 使用，不对外暴露。

#include <sqlite3.h>

#include <string>

// alerts 表列探测结果（老库兼容：缺列查询侧补空串）
struct AlertsColumns {
    bool user_name = false;
    bool uid = false;
    bool exe = false;
    bool container_id = false;
    bool ancestors = false;
    bool attack = false;
    bool severity_origin = false;
    bool escalated = false;
    bool escalation_reason = false;
};

// PRAGMA table_info 探测 alerts 表已有列
AlertsColumns ProbeAlertsColumns(sqlite3* db);

// 组装 alerts 查询 SELECT 列表：既有 14 列顺序逐字节不变，进程上下文扩展列
// （exe/container_id/ancestors）追加在 recorded_at 之后；老库缺列补空串。
std::string BuildAlertsSelect(const AlertsColumns& cols);
