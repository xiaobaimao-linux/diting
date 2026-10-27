# case-07 富化竞态分析（W8 S3 收口）

对应缺口登记：rule-engine-gaps.md G24。修复提交：0bafd35（2026-10-26）。

## 现象

exe 名单类规则（under_interpreter 等）对 case-07 间歇漏报：bash exec 事件被渲染成
`/usr/bin/id`，按解析结果评估不命中。

## 根因

`process.exe` 富化在消费线程读 `/proc/<pid>/exe` 解析。短寿进程原地再 exec
（`bash -c <cmd>` 的末命令优化，同 pid 连续两次 exec）时，消费侧读到的是再 exec
之后的新映像。内核侧无丢包（proc reserve_failed=0），排除传输层；事件落库与
祖先链均正常，问题只在"评估所依据的 exe"这一刻的取值。

## 修复

`eval_rules_on_exec_event` 未命中、且事件自带 `pe.exe`（exec 时刻 tracepoint
filename，无竞态）与 /proc 解析结果不一致时，以 `pe.exe` 复评一次
（src/baseline/monitor.cpp:1527-1531）。G8 单命中路径不受影响。

- 修复前复现：7/10 漏报
- 修复后回归：10/10 命中

## 已知残留边界

落库渲染维持 /proc 解析优先（G21 语义不变），竞态窗口内落库的 exe 可能是再
exec 后的新映像。v2 方向：BPF 侧在 exec 上下文用 bpf_d_path 取解析后路径随事件
携带，用户态不再事后读 /proc。

## 同族遗留

case-06（进程退出竞态，container_id 富化时进程已退出）同为 /proc 事后读取竞态，
根治排期 W9（见 docs/integration-test-plan-w9.md §case-06 根治排期）。
