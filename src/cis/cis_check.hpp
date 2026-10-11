#pragma once

#include <string>
#include <vector>

namespace cis {

struct CisCheckDef {
    std::string id;
    std::string category;
    std::string description;
    std::string command;
    std::string expected;
    std::string severity;
    std::string compliance;
};

// 解析 CIS 检查定义 YAML（顶层 checks: 列表），校验七字段非空且 severity 为 high/medium/low。
bool LoadCisChecks(const std::string& path, std::vector<CisCheckDef>& out, std::string& err);

} // namespace cis
