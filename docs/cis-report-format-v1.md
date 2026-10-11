# CIS 基线报告导出格式契约 v1

`baseline-guard cis report` 自 schema_version=1 起支持 `--format text|json|html` 与 `--out <文件>`：

- `--format text`（默认）：终端表格，行为与旧版一致；指定 `--out` 时表格写入文件。
- `--format json`：输出本文档定义的 v1 契约 JSON；`--out` 缺省时写到 stdout。
- `--format html`：自包含单文件 HTML（`<meta charset="utf-8">`，内联 `<style>`，无任何外部依赖/外链）；`--out` 缺省时写到 stdout。
- 旧 `--json` 开关行为保持不变（report 输出纯数组，check 输出原对象），向后兼容；`--format` 与 `--json` 同时给出时 `--format` 优先。
- 数据源：`CisStore::GetLatest(severity_filter, result_filter)`，`--level`/`--result` 过滤对三种格式同样生效。

## JSON 契约（schema_version=1）

顶层对象，字段名固定，一字不改：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| tool | string | 固定 `"baseline-guard"` |
| report | string | 固定 `"cis-baseline"` |
| schema_version | number | 固定 `1` |
| generated_at | string | ISO8601 本地时间（`YYYY-MM-DDTHH:MM:SS`），报告生成时刻 |
| host | string | 生成报告的主机名 |
| summary | object | 汇总统计，见下 |
| results | array | 明细，按 `check_id` 升序排序 |

`summary`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| total | number | 检查项总数 |
| pass / fail / warn | number | 各结果计数 |
| pass_rate | number | 通过率（pass/total），保留 4 位小数（double），total=0 时为 0 |
| by_severity | object | 键固定含 `high`/`medium`/`low`，值为 `{total, pass, fail, warn}`，统计该级别下各结果数 |

`results[]` 元素：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| check_id | string | 检查项 ID，如 `AUTH-01` |
| category | string | 分类（AUTH/SSH/LOG/NET/FILE/MISC） |
| description | string | 检查项描述 |
| severity | string | `high` / `medium` / `low` |
| compliance | string | 等保 2.0 条款号；无直接对应时为 `无直接对应` |
| result | string | `pass` / `fail` / `warn` |
| expected | string | 预期值（含修复指引），取自定义六字段 expected 列 |
| remediation | string | 修复建议；与 `expected` 同源，取自定义六字段 expected 列 |
| actual | string | 实际输出（单行截断至 200 字符） |
| reason | string | 判定理由 |
| checked_at | string | 检查时间（ISO8601） |
| host | string | 检查执行主机名 |

### 最小示例

```json
{
  "tool": "baseline-guard",
  "report": "cis-baseline",
  "schema_version": 1,
  "generated_at": "2026-10-11T10:00:00",
  "host": "demo-host",
  "summary": {
    "total": 40,
    "pass": 19,
    "fail": 21,
    "warn": 0,
    "pass_rate": 0.475,
    "by_severity": {
      "high": {"total": 8, "pass": 3, "fail": 5, "warn": 0},
      "medium": {"total": 24, "pass": 12, "fail": 12, "warn": 0},
      "low": {"total": 8, "pass": 4, "fail": 4, "warn": 0}
    }
  },
  "results": [
    {
      "check_id": "AUTH-01",
      "category": "AUTH",
      "description": "确保已启用密码复杂度策略",
      "severity": "high",
      "compliance": "8.1.9.2",
      "result": "fail",
      "expected": "minlen>=8 且含字符类要求；修复：编辑 /etc/security/pwquality.conf",
      "remediation": "minlen>=8 且含字符类要求；修复：编辑 /etc/security/pwquality.conf",
      "actual": "minlen=6",
      "reason": "实际值不满足预期",
      "checked_at": "2026-10-11T09:59:58",
      "host": "demo-host"
    }
  ]
}
```

## HTML 契约

- 自包含单文件：`<meta charset="utf-8">`，样式全部内联于 `<style>`，无 `http://`/`https://` 外部引用，无脚本依赖。
- 汇总区：检查项总数、通过率（%）、pass/fail/warn 计数、high/medium/low 各级别分布。
- 明细表列：ID / 分类 / 描述 / 结果 / 级别 / 等保 2.0 条款号 / 修复建议 / 实际输出 / 判定理由 / 检查时间（修复建议取自定义六字段 expected 列）。
- 行级配色：fail 行 `tr.fail{background:#fdd}` 且结果单元格红色加粗（`td.result.fail`）；warn 行琥珀色（`tr.warn`）；pass 行浅绿（`tr.pass`）。
- 所有落库字段渲染前做 HTML 转义（`& < > " '` → `&amp; &lt; &gt; &quot; &#39;`）。

## 实现位置

- 渲染：`src/cis/cis_report.cpp`（`cis::RenderCisReportJson` / `cis::RenderCisReportHtml`）。
- 参数解析与写文件：`src/cis/cis_main.cpp` 的 `RunReport()`。
