# v1.0 范围决策（2026-10-14 拍板，W8 收官复核确认）

> 拍板日期：2026-10-14；复核日期：2026-10-27。依据：`docs/v1-scope-options.md`
> （三方案备料）、`docs/v1-gap-list.md`（方案 A 预排清单）、W6–W8 实测记录、
> 云主机 6.8/5.15 双端实测（W8 S4）。本文档登记 W8 收官对 10-14 拍板的复核确认：
> 结论维持不变，仅补充实测证据。

## 决策：维持 B+C 混合方案

**v1.0 范围**：以方案 B（收缩版）为骨架、取方案 C 的 AI 专项规则包——遥测
（exec/network/dns/privilege/ns）+ FIM + 规则引擎 DSL v1 + core 规则包 30 条
（含 AI 专项 6 条）+ 36 攻击用例两轮回归 + CIS 基线 40 项 + AI 资产发现与告警升级
——即当前已全部落地并全绿的交付物，全部保留。

**砍出 v1.0 的部分**：

- perf buffer 降级版（priv_watch/net_watch/proc_watch perf 通道）——转 v1.x 候选；
- CentOS7/openEuler 兼容矩阵——kernel-compat-matrix 对应黄格红格转"v1.x 候选"，
  支持口径为 **内核 ≥5.8 全功能，<5.8 不支持**；兼容实测只承诺 Ubuntu 系
  22.04/24.04 两档（已有 5.15/6.8 云主机实测背书）；
- 5.4 已有的 lsm_kprobe 降级代码保留但不进 v1.0 验收口径；
- 方案 C 只取 AI 专项规则包 6 条（W8 S2 已落地）：M4-1 模型完整性保护 /
  M4-2 模型加载监控不进 v1.0——AI 差异化由 AI 资产发现 + 告警升级 +
  该规则包兑现，无需新增开发范围。

**时间口径**：目标 2026 年 12 月上旬。

## 决策依据

1. **零返工。** 方案 B 覆盖的全部范围（36 用例、CIS 40 项、遥测/FIM/规则引擎/AI 链路）
   已在 W8 周检全绿（回归 r1 35/36+r2 36/36 唯一失败为已知 flake、unit/integration/e2e
   exit=0、CIS pass 19/fail 21 无回归、bus.hi 四路全 0、RSS 峰值 147.0MB 在红线内）。
   B+C 混合的全部零件已齐：方案 B 骨架零返工，方案 C 只引入已交付的 AI 规则包。
2. **砍掉的是最大风险源。** perf 降级版是唯一未动工的内核类硬骨头，而内核类工作估时
   持续被低估（W3 性能攻坚吃掉 W4 前两天、W8 S4 三个计划外兼容 bug 再次复现前科）。
   砍掉它等于移除出口前最大的滑期变量。
3. **"≥5.8"声明已有实测背书。** W8 S4 云主机实测：6.8（24.04）与 5.15（22.04）双端
   ring buffer 主路径加载运行正常（proc_watch CO-RE 修复后三端 attached，5.15 的
   chown hook 走自动降级）。支持矩阵第一行不是口号，是两台在跑的长跑机。
4. **兼容性叙事的代价可接受。** 4.18/5.4 存量用户（RHEL8/20.04 ESM）暂缓支持是真实代价，
   但 4.18 档本身依赖 RHEL8 BTF backport 实测、结论可能是"不支持"——把一个可能落不了地
   的承诺写进 v1.0 口径是负债而非资产；v1.x 补做时以实测结论说话。
5. **12 月上旬发布保住社区里程碑。** "eBPF 主机安全：规则包 + CIS + AI 资产开箱即用"
   的故事线完整；方案 C 的其余新增范围（mmap 钩子 5.9+ 行为、模型目录批量 inode 注册）
   本身又是两个未验证的内核/工程风险点，不进 v1.0。

## 已知边界清单（v1.0 发布材料须如实声明）

### 攻击用例层（tests/attack-cases/README.md §已知边界）

- **case-06 flake（进程退出竞态）**：容器内毫秒级短寿进程的 container_id 富化读 /proc 竞态，
  告警/事件 container_id 间歇为空（W8 周检实测间歇 ~50%：r1 FAIL、r2 PASS、重跑 1 PASS 1 FAIL）。
  与内核丢包无关。根治排 W9 D1–D3（内核侧事件时刻捕获 task cgroups），见
  `docs/integration-test-plan-w9.md` §4。
- **case-04 AF_UNIX 边界**：net_watch 只覆盖 TCPv4 connect/accept/bind + DNS，docker.sock
  等 AF_UNIX 连接无网络事件；容器场景判定信号为 exec 链 + 祖先链容器运行时归属。
- **argv/cmdline 边界**：exec cmdline 前 255 字节已采集（G19，W8 S1），但 shell 内建命令
  （`history -c` 等）不产生 exec 事件、不可见；chattr +i/-i、kill-security-tool 目标名
  两条规则仍按 exe/comm 退化形态（G19 残余草案，v2 逐条改写）。

### 规则引擎层（docs/rule-engine-gaps.md，截至 W8 收官）

已关闭/定型：G3（四类事件接入引擎）、G8（单命中为显式设计）、G10、G11、G15、G16、G17、
G18、G19 主体（cmdline 落地）、G21（exe/comm 分工定型）、G24 主体（pe.exe 复评兜底）。

仍 open（v1.0 接受现状，v2 方向已登记）：

- G1 残余（shell 内建命令不可见）、G2（无 fd/socket 关联）、G4（无 endswith/glob）、
  G5（无跨事件关联，v1 非目标）；
- G6 残余（startswith/contains 前缀语义依赖既有 inode 登记）、G7（无路径变量/宏）；
- G9（truncate/O_TRUNC 不产生 file.write，降级方案 inode_setattr 钩子排 W10 后）；
- G12（无位运算操作符，ns.flags 组合位靠枚举）、G13（exec 无 env 采集）、
  G14（module_load 无模块路径）；
- G20（无 CIDR 比较）、G22（DSL 无法引用 config 字段）、G23（无 ai_workload 资产判定，
  AI 规则按 comm 近似）；
- G24 残余（竞态窗口内落库 exe 可能是再 exec 后的新映像，/proc 解析优先语义不变）。

### 内核兼容层（W8 S4 实测登记）

- **proc_watch 布局兼容边界**：旧内核（定长数组版布局，如 6.8）fork 事件 comm 走固定数组
  读取路径，新内核走 __data_loc 路径，bpf_core_field_exists 判布局分发；6.8 BTF 缺
  sched_process_exit 结构体，exit 事件按无 BTF 兜底。两端语义一致、实现路径不同。
- **5.15 CHOWN 降级**：5.15 verifier 不支持 LSM hook 原型按值 STRUCT 参数，file_chown_hook
  禁载、CHOWN 检测降级（自动重试机制，日志可查）；其余三探针不受影响。
- **构建要求**：Ubuntu 22.04 自带 libbpf 0.5 不可用（缺 perf_buffer__new 六参与 ring__*
  API），需 libbpf 1.8 源码静态链接构建。
