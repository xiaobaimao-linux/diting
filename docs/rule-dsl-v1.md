# 规则 DSL v1 设计

> 状态：v1.0（W4 D3）
> 字段来源：`docs/event-schema-v1.md`（唯一字段来源，禁止新造字段名）
> 实现：src/detect/（解析器 + 匹配引擎），示例：rules/examples/

## 1. 设计目标

1. 声明式描述"什么事件算可疑"，用户不改代码即可加检测规则。
2. 语法风格对齐 Falco（rule/desc/condition/output/priority 五字段），降低安全用户的学习成本（PRD M3-9）。
3. 每条规则携带 ATT&CK 映射、严重等级、误报说明、处置建议（PRD M3-10）。
4. 规则即文件，YAML 格式，目录加载，可随配置热加载（复用 SIGHUP 快照替换模式）。
5. 求值零堆分配热点路径可控：接入消费线程后总 CPU 增量可测、可压回。

## 2. 语法

一个规则文件是一个 YAML 列表，可含多条规则：

```yaml
- rule: Read Etc Shadow
  desc: 非白名单进程读取 /etc/shadow
  condition: event_type = file.read and file.path = /etc/shadow and not process.exe in (/usr/bin/passwd, /usr/sbin/sshd)
  output: "敏感文件读取 (rule=%rule.name exe=%process.exe uid=%process.uid file=%file.path container=%container.container_id)"
  priority: high
  attack: [T1003, T1552]
  fpr_note: 备份软件、配置管理工具（ansible/puppet agent）可能周期性读取，建议把对应 exe 加入白名单列表
  response: 确认进程合法性；非预期进程则排查提权路径，检查该进程后续网络外联
```

顶层字段：

| 字段 | 必填 | 说明 |
|---|---|---|
| `rule` | 是 | 规则名，全局唯一；加载时重复即报错 |
| `desc` | 是 | 一句话描述 |
| `condition` | 是 | 条件表达式，语法见 §4 |
| `output` | 是 | 告警文本模板，`%字段路径` 插值（见 §5） |
| `priority` | 否 | 严重等级，见 §6（W5 D3 起可选，缺省 `medium`） |
| `attack` | 是 | ATT&CK 映射，见 §6 |
| `fpr_note` | 是 | 误报说明（什么正常行为会命中、怎么调） |
| `response` | 是 | 处置建议 |

规则文件放置于 `rules/` 目录（引擎配置 `rules_dir`），`*.yaml`/`*.yml` 全部加载；任一文件解析失败：严格模式整体拒绝加载（保留旧快照），宽松模式跳过该文件（供 CLI check）。

W7 D1 起 monitor 启动路径 fail-fast：任一规则文件加载失败、或 enabled 但加载 0 条规则，直接报错拒绝启动（不再降级空引擎）；热加载失败仍保留旧快照。

W7 D1 起文件路径自动登记：condition 中 `file.path` 的 `=`/`in` 字面量路径在加载/热更新时自动登记进内核 inode map（无需先跑 snapshot 基线或 config `rules:` 注册）；规则移除时反登记（config/基线同引用的不误删）。不可登记路径（不存在 / 非绝对 / 含通配符）加载期逐条 warn，该规则降级为"文件条件不生效"，不阻断其余规则。`startswith`/`contains` 前缀语义不在自动登记范围（见 rule-engine-gaps.md G6）。

## 3. 字段表

条件表达式与 output 模板中可引用的字段 = `docs/event-schema-v1.md` 全表，常用节选：

| 字段路径 | 类型 | 说明 |
|---|---|---|
| `event_type` | string | file.read / file.write / file.chmod / file.chown / file.unlink / file.rename / file.mmap / process.exec / network.connect / network.accept / network.bind / network.dns / priv.setuid / priv.setgid / priv.capset / priv.ptrace / priv.module_load / ns.mount / ns.unshare / ns.setns |
| `process.pid` / `process.ppid` / `process.uid` / `process.gid` | number | |
| `process.comm` / `process.exe` | string | comm ≤16 字符可能截断，身份匹配优先 exe |
| `process.ancestors[].pid` / `process.ancestors[].comm` / `process.ancestors[].exe` | string/number | `[]` 表示祖先链任一元素（≤8 层，自近及远） |
| `container.container_id` | string | 宿主机进程缺失，按空串处理 |
| `file.path` / `file.action` / `file.new_mode` | string | file.new_mode 为 9 字符 rwx 符号串，如 `file.new_mode = rwxr-xr-x`；setuid/setgid/sticky 高位被 &0777 掩掉，无 s/t 形式（04755 与 0755 均渲染为 rwxr-xr-x，SUID 不可判定，见 G11） |
| `file.ino` / `file.mask` / `file.new_uid` / `file.new_gid` | number | |
| `network.sip` / `network.dip` | string | 点分文本 |
| `network.family` / `network.protocol` / `network.sport` / `network.dport` | number | protocol: 6=TCP 17=UDP |
| `dns.domain` | string | 点分文本 |
| `dns.qtype` | number | |
| `priv.target_id` / `priv.effective_lo` / `priv.target_pid` / `priv.request_value` | number | |
| `priv.request` / `priv.name` | string | request 如 PTRACE_ATTACH；name 为模块名 |
| `ns.source` / `ns.target` / `ns.fstype` / `ns.nstype_name` / `ns.target_ns` | string | |
| `ns.flags` / `ns.fd` / `ns.nstype` | number | |
| `ns.names[]` | string | 数组元素本身为字符串（去 `CLONE_` 前缀名），如 `ns.names[] = NEWNS`、`ns.names[] = NEWUSER` |

规则引用了表中不存在的字段 → 加载期报错（文件名:行号 + 未知字段）。
`event_type` 的 `=` / `in` 字面值不在上表事件类型内 → 加载期报错（未知事件类型，W7 G3 根因防御：杜绝"写了不触发也不报错"）。

## 4. 条件表达式语法

EBNF：

```
expr        := or_expr
or_expr     := and_expr ( "or" and_expr )*
and_expr    := not_expr ( "and" not_expr )*
not_expr    := "not" not_expr | "(" expr ")" | comparison
comparison  := operand compare_op operand
compare_op  := "=" | "!=" | "in" | "contains" | "startswith"
operand     := field_path | literal
field_path  := ident ( "." ident )* ( "[]" ( "." ident )+ )?
literal     := bare_string | number | list
list        := "(" literal ( "," literal )* ")"        # 仅作 in 的右操作数
```

语义约定：

- 关键字 `and`/`or`/`not`/`in`/`contains`/`startswith` 小写，是保留字。
- 字面值：`/etc/shadow`、`0644`、`bash` 这类裸串直接书写（允许字符：字母数字与 `/._-:*+=@` 等，遇空白/括号/逗号截止）；纯数字解析为 number，其余为 string。v1 不支持引号转义字符串（路径含空格的场景留给 v2）。
- 比较类型：`= !=` 支持 string 与 number；`in` 右操作数必须是列表；`contains startswith` 仅 string。
- `[]` 后缀：对数组字段（v1 仅 `process.ancestors`、`ns.names`）表示"任一元素满足即真"。
- 缺失字段：事件无该字段时，string 按空串求值，number 比较一律为 false。推论：`container.container_id != ""` 在宿主机进程上为 false，容器内为 true——这是判断"容器归属事件"的标准写法。
- 短路：`and` 左 false、`or` 左 true 即停，右操作数不再求值。
- 宏（macro）：v1 **不支持**。理由：宏是 Falco 规则复用的主要复杂度来源（嵌套展开、覆盖语义、循环引用检测），v1 规则集小（≤100 条），重复条件用 list 已能覆盖；W6 规则包扩充时再评估。
- 列表（list）：v1 **支持**，但仅作为 `in` 的内联右操作数，不支持命名 list 定义与跨文件引用。

## 5. output 模板

`%字段路径` 插值，字段集同 §3，另加两个伪字段：`%rule.name`（规则名）、`%rule.priority`。缺失字段渲染为空串。数组字段不支持插值（告警里祖先链由引擎按现有 alerts.ancestors 列单独携带，与 FIM 告警一致）。

## 6. 规则元数据

- `priority`（严重等级）：枚举 `critical | high | medium | low`；可选，缺省补 `medium`（解析不报错，W5 D3）。枚举定义见公共头 `src/common/severity.hpp`。
  - 偏离 Falco 的说明：Falco 是八级（EMERGENCY…DEBUG），v1 裁剪为四级，与现有 alerts 表 severity 取值体系（low/medium，W3 起）一致，避免 priority/severity 双字段冗余与映射表维护。落库 alerts.severity 存原值。
- `attack`：ATT&CK 技术 ID 列表，元素形如 `T1059`、`T1003.001`（子技术可带点号）；战术层可选，写作 `TA0002`。仅做映射标注与落库（alerts.attack 列，W4 新增），v1 不做 tactic 推导。
- `fpr_note`：误报说明——什么正常业务行为会命中、建议的调参方向（加白名单/收窄路径）。
- `response`：处置建议——命中后人工排查的第一步与升级路径。

## 7. 非目标（v1 明确不做）

1. 跨事件关联（如"exec 后 60s 内出现 connect"）——需要状态机与时间窗，留 W6+。
2. 速率阈值（如"5 分钟内失败登录 >10 次"）——依赖聚合计数器，留 W6+，与 M5-3 聚合降噪协同设计。
3. 宏（macro）与命名 list 的跨文件复用——见 §4。
4. 字段函数/正则/glob（如 `glob(/etc/*)`）——v1 用 startswith 覆盖路径前缀场景。
5. 引号字符串与转义——见 §4。
6. 内核态求值（规则下推 BPF）——v1 全部用户态求值。
7. 规则对告警的自动处置（block/kill）——v1 规则引擎只产告警，action 仍由既有 LSM 策略路径决定。

## 8. 匹配语义：单命中 + 命中域互斥约定（显式设计，W7 D2 定稿）

**单事件只报首个匹配规则**，这是 v1 的显式设计而非缺陷：

- 求值顺序：规则按 `event_type` 类别分桶，桶内按加载顺序（rules 目录路径字典序：`core < examples < perf-100 < storm`，同目录按文件序/文件内序）；`Evaluate` 返回第一条命中规则即停，告警侧只发这一条。
- 约定：**同一事件类别下，规则编写者须保证命中域互斥或接受遮蔽**——重叠规则中先加载者吃掉事件，后加载者静默无告警。编写新规则时检查同类别既有规则的 condition 重叠关系（core 内 8 条规则已按此互斥设计）。
- 决策依据（2026-10-12 实测统计，Evaluate 临时改收集模式跑 22 用例 × 2 轮，只统计不改语义）：242 个命中事件中多命中 54 个（22.3%），但 38 个是 perf-100 压测规则的人为同构重叠（无实际意义），14 个是 core 遮蔽 examples（加载序即预期优先级），core-vs-core 重叠仅 2 事件且同属 reverse-shell 家族、告警不丢检测只丢归属粒度。多命中 >20% 但**无实际遮蔽危害**，故不改全命中；v2 如需多命中，Evaluate 返回命中列表 + 告警侧按规则去重/节流（见 gaps 文档 G8）。
