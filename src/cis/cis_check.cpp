#include "cis_check.hpp"

#include <yaml-cpp/yaml.h>

#include <sstream>

namespace cis {

namespace {

bool ReadRequiredScalar(const YAML::Node& node, const char* key, std::string& out,
                        std::string& err, size_t index) {
    const YAML::Node v = node[key];
    if (!v || !v.IsScalar()) {
        std::ostringstream oss;
        oss << "checks[" << index << "] 缺少字段: " << key;
        err = oss.str();
        return false;
    }
    out = v.Scalar();
    if (out.empty()) {
        std::ostringstream oss;
        oss << "checks[" << index << "] 字段为空: " << key;
        err = oss.str();
        return false;
    }
    return true;
}

} // namespace

bool LoadCisChecks(const std::string& path, std::vector<CisCheckDef>& out, std::string& err) {
    out.clear();
    err.clear();

    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const std::exception& ex) {
        err = std::string("解析定义文件失败: ") + ex.what();
        return false;
    }

    const YAML::Node checks = root["checks"];
    if (!checks || !checks.IsSequence()) {
        err = "定义文件缺少顶层 checks 列表: " + path;
        return false;
    }

    for (size_t i = 0; i < checks.size(); ++i) {
        const YAML::Node node = checks[i];
        CisCheckDef def;
        if (!ReadRequiredScalar(node, "id", def.id, err, i)) return false;
        if (!ReadRequiredScalar(node, "category", def.category, err, i)) return false;
        if (!ReadRequiredScalar(node, "description", def.description, err, i)) return false;
        if (!ReadRequiredScalar(node, "command", def.command, err, i)) return false;
        if (!ReadRequiredScalar(node, "expected", def.expected, err, i)) return false;
        if (!ReadRequiredScalar(node, "severity", def.severity, err, i)) return false;
        if (!ReadRequiredScalar(node, "compliance", def.compliance, err, i)) return false;
        if (def.severity != "high" && def.severity != "medium" && def.severity != "low") {
            std::ostringstream oss;
            oss << "checks[" << i << "] 非法 severity: " << def.severity
                << " (期望 high/medium/low)";
            err = oss.str();
            return false;
        }
        out.push_back(def);
    }
    return true;
}

} // namespace cis
