#pragma once

#include <string>
#include <vector>

#include "rule.hpp"

// ── 规则目录加载器（docs/rule-dsl-v1.md §2/§6）──────────────────────
namespace detect {

// 严格模式：加载 dir 下全部 *.yaml/*.yml（文件名排序，稳定顺序），
// 任一文件/任一规则出错整体失败。成功返回 true 并填充 out；
// 失败返回 false，err 格式 "文件名:行号: 原因"（行号取 yaml 节点行，
// condition 语法错误取 condition 节点行）。
// 校验：必填八字段（rule/desc/condition/output/priority/attack/
// fpr_note/response）、priority 枚举、字段路径对照 schema 字段表
// （含 output 模板插值字段）、规则名全局查重。
bool LoadRulesDir(const std::string &dir, std::vector<Rule> &out, std::string &err);

// ── DSL 文件规则路径提取（W7 D1 缺口一：自动登记内核 inode map）─────
// 一条 file.path 字面量引用：来源规则名 + 路径文本。
struct FilePathRef {
    std::string rule_name;
    std::string path;
};

// 提取全部规则 condition 中 file.path 的 = / in 字符串字面量，作为内核
// monitor_actions map 的登记候选。仅精确路径可登记；startswith/contains
// 是前缀/子串语义而非具体路径，不在候选内（见 docs/rule-engine-gaps.md G6）。
// != 语义为"除该路径外"，无法登记，同样跳过。
std::vector<FilePathRef> ExtractFilePathRefs(const std::vector<Rule> &rules);

// 登记候选路径的静态分类（任务 4 兜底警告用）：
// Ok 可登记（交调用方 stat）；Glob 含通配符 * ? [ ]（v1 不支持，明确拒绝）；
// NotAbsolute 非绝对路径。
enum class PathRefClass { Ok, Glob, NotAbsolute };
PathRefClass ClassifyPathRef(const std::string &path);

} // namespace detect
