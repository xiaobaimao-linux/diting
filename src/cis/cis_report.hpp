#pragma once

#include <string>
#include <vector>

#include "cis_store.hpp"

namespace cis {

// 渲染 CIS 基线报告为契约 JSON（schema_version=1，字段契约见 docs/cis-report-format-v1.md）
// remediation 字段取自定义六字段 expected 列；results 按 check_id 排序
std::string RenderCisReportJson(const std::vector<CisResultRow>& rows, const std::string& host);

// 渲染自包含单文件 HTML（内联样式、无外部依赖；fail 行红色高亮，warn 琥珀色，pass 浅绿）
// 所有落库字段均做 HTML 转义（& < > " '）
std::string RenderCisReportHtml(const std::vector<CisResultRow>& rows, const std::string& host);

} // namespace cis
