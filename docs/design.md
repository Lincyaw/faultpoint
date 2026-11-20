# faultpoint 设计

faultpoint 在被测系统的代码中放置故障点。同一个故障点既能按规则注入故障，也能在故障自然发生时上报观测，因此一次注入实验引起的“额外故障”可以用与注入相同的词汇表达，为反事实的因果边发现提供数据。

本仓库只负责故障点本身：类别、身份、规则、观测与插桩。实验编排、因果边的统计、拼接搜索和落地成题由使用它的搜索系统负责；`faultpoint diff` 只提供一次反事实比较的参考实现。

## 1. 故障点的类别

### 1.1 位置与偏差

故障点的类别由两个维度张成：位置是故障发生在哪种边界上，偏差是发生了什么样的偏离。

| 位置 \ 偏差 | 失败/遗漏 | 变慢 | 值错误 | 重复 | 乱序 | 部分完成 |
| --- | --- | --- | --- | --- | --- | --- |
| 进程内控制：`branch` `call` `check` `loop` | `fail` | `delay` | `negate` | — | — | — |
| 进程内取值：`value` `clock` | — | — | `set` `shift` | — | — | — |
| 资源与准入：`acquire` | `fail` | `delay` | — | — | 以 `delay` 表达 | — |
| RPC：`rpc_client` `rpc_server` | `fail` | `delay` | 规划中 | `duplicate` | 以 `delay` 表达 | `fail_after` |
| 存储：`store_read` `store_write` | `fail` `drop` | `delay` | `empty` | `duplicate` | 以 `delay` 表达 | `fail_after` |
| 消息：`publish` `consume` | `fail` `drop` | `delay` | — | `duplicate` | 以 `delay` 表达 | `fail_after` |
| 进程生命周期 | `crash`（任何故障点都可执行） | | | | | |

- 乱序不单设动作：对某个键的消息或请求做 `delay`，使它晚于后继到达。
- 并发竞争同样用 `delay` 表达：在“读之后、写之前”的 `store_read` 或 `acquire` 上延迟，以拉大竞争窗口。
- 部分完成指效果已经发生、调用方却收到失败，例如对端已执行而响应丢失，或者双写只完成一半。它是非幂等重试与数据不一致的主要来源。

### 1.2 三种角色

拼接要求一段传播的起点能在另一次实验中被局部伪造。按这个要求，现象分为三种角色：

| 角色 | 含义 | 例子 |
| --- | --- | --- |
| 故障点 | 可注入、可观测，能作为拼接的中间环节 | 上表各类 |
| 终点 | 只可观测，是用户可见的结果 | 入口服务 `rpc_server` 的响应状态 |
| 条件 | 无法在一个点上伪造，只能作为负载或部署参数 | 共享资源被其他租户占满、集群节点数 |

### 1.3 各类故障点

| 类别 | 放置位置 | 可用动作 | 观测结果（outcome） |
| --- | --- | --- | --- |
| `branch` | 守卫错误返回或抛出的条件判断 | `fail`：强制进入该分支 | `taken` `not_taken` |
| `call` | 返回错误值的调用点（Go 的 `err`） | `fail`：替换为错误值 | `error` `ok` |
| `check` | 返回布尔值的检测函数 | `negate` | `true` `false` |
| `loop` | 循环体开头 | `delay`：每次迭代延迟 | `iteration` |
| `value` | 业务计算结果（人工标注） | `set` `shift` | `observed`，数值记入 total |
| `clock` | 读取当前时间 | `shift`（秒） | `read` |
| `acquire` | 连接池、锁、限流器的获取（人工标注） | `fail` `delay` | `acquired` `rejected` |
| `rpc_client` | HTTP/RPC 客户端 | `fail` `delay` `fail_after` `duplicate` | `2xx` `4xx` `5xx` `timeout` `refused` `error`，延迟毫秒记入 total |
| `rpc_server` | HTTP/RPC 服务端入口 | `fail` `delay` `fail_after` | 同上 |
| `store_read` | 读语句 | `fail` `delay` `empty` | `rows` `empty` `error`，行数记入 total |
| `store_write` | 写语句 | `fail` `delay` `fail_after` `drop` `duplicate` | `ok` `error`，影响行数记入 total |
| `publish` `consume` | 消息生产与消费 | `fail` `delay` `fail_after` `drop` `duplicate` | `ok` `error` |

所有类别都可以执行 `delay` 和 `crash`。值错误中，只有布尔取反（`negate`）由插桩自动放置；一般的业务计算错误空间大、误报多，因此 `value` 只放在人工标注的、在业务约束上有意义的计算上（金额、配额、时间窗口、版本号），并且只在合法值域内扰动。

### 1.4 完整性检查

类别表的完整性无法证明，只能对照检查。每遇到一个已知案例（公开的故障研究、已有题目），逐跳检查是否能用上表的某一格表达；表达不了的一跳，说明缺少一个类别或动作。

## 2. 故障点的身份

故障点 id 的格式为 `<service>:<kind>:<locator>`，类别是 id 的一部分，所以规则加载时就能检查动作是否适用。

| 来源 | locator |
| --- | --- |
| 改写器放置的进程内故障点 | `<相对路径>:<函数限定名>#<锚点>`，`check` 每个函数一个，省略锚点 |
| HTTP 边界 | `<METHOD> <路径模板>`，客户端前面再加对端主机；路径中的数字、UUID 和长十六进制段替换为 `{}` |
| SQL 边界 | `<表名，以 + 连接>#<规范化语句的哈希>` |

锚点是节点规范化形式（不含行号）的哈希前 8 位。同一函数中出现相同哈希时，追加序号。这样，与该节点无关的代码修改不会改变 id。改写器同时输出一份清单（`faultpoint-manifest.json`），逐个列出故障点的 id、类别、文件、行号、函数和代码片段，供实验规划读取。

## 3. 规则

一个规则文件是一个实验（`RuleSet`），格式由 `spec/rules.schema.json` 定义：

```json
{
  "experiment": "inv-empty-1",
  "rules": [
    {
      "id": "r1",
      "point": "inventory:store_read:stock#1a2b3c4d",
      "action": {"kind": "empty"},
      "scope": {"fp.scope": "tenant-a"},
      "trigger": {"skip": 0, "limit": 5, "probability": 1.0}
    }
  ]
}
```

- **范围**：`scope` 中的每一项都必须等于当前请求 baggage 中的同名项，规则才生效。不在任何请求中的后台工作没有 baggage，只匹配 `scope` 为空的规则。
- **触发**：每个进程对每条规则单独计数：先跳过前 `skip` 次匹配，之后最多注入 `limit` 次，每次以 `probability` 的概率注入（随机数以 `FAULTPOINT_SEED` 和规则 id 为种子）。并发下“第 n 次”本身是不确定的，所以优先用 `scope` 限定到具体的租户或请求，少用计数。
- **适用性**：动作必须属于该类别的可用动作（见 1.3）。边界类故障点的 `fail` 和 `fail_after` 用 `status` 指定合成的响应状态，或用 `error` 指定 `timeout` 或 `refused`。`call` 的 `error` 是已登记的错误名，Go 改写器会把包级的 `error` 变量自动登记为 `<包路径>.<变量名>`，这样注入的就是代码真实会返回的哨兵错误。
- **原子更新**：控制方先写临时文件再改名替换。SDK 每 0.5 秒检查一次文件的修改时间，重新加载前先把当前计数写出，因此每条观测记录只属于一个实验。规则文件无效时，SDK 终止进程，以免实验在无效的规则下继续运行。

## 4. 观测

故障点每被执行一次，就记录一个结果。结果在进程内按（实验，故障点，outcome，范围，注入规则）聚合成计数和 total，每隔 `FAULTPOINT_FLUSH_SECONDS` 秒，以 JSON Lines 的形式追加到 `FAULTPOINT_REPORT`，格式由 `spec/observation.schema.json` 定义。

- **范围**：取 baggage 中 `FAULTPOINT_SCOPE_KEY`（默认 `fp.scope`）的值，用于在同一次部署中区分被注入的请求与作为对照的请求。
- **注入规则**：被注入的那次执行，记录中带有规则 id；自然发生的执行，这一项为空。比较时可以把注入本身和它引起的效果分开。
- **样例**：当前上下文中有有效的 trace 时，每个键最多保留 5 个 trace id，用于把效果追溯到具体请求。
- **独立管道**：观测写入单独的文件，不进入被测系统的日志、追踪和指标，避免进入诊断者可以申请的数据。

## 5. 上下文

请求上下文使用 OpenTelemetry 的 W3C baggage 和 traceparent。

- 已经接入 OpenTelemetry 的系统，由它原有的插桩负责跨服务传递。SDK 只读取上下文，不依赖 OpenTelemetry SDK。
- 没有接入的系统，由本仓库的 HTTP 边界拦截器负责提取和注入这两个请求头。
- Python 的上下文基于 contextvars，能随协程和线程池传递。
- Go 必须显式传递 `context.Context`。改写器使用所在函数的 `context.Context` 参数或 `*http.Request` 参数的 `Context()`；找不到时传入 `nil`，这时故障点只匹配 `scope` 为空的规则，观测的范围为空。

## 6. 插桩

| 位置 | 方式 | 理由 |
| --- | --- | --- |
| 边界：HTTP、SQL、消息、资源 | 各语言客户端库和框架的拦截器 | 每个库只做一次，与业务代码无关 |
| 进程内：`branch` `call` `check` `loop` `clock` | 每种语言一个改写器，在构建期改写一份源码副本 | 不修改提交的业务代码 |
| 进程内：`value` `acquire` | 开发者手工调用 API | 需要业务含义，无法自动判断 |

**两份构建**：插桩只用于探索阶段的构建。出题时使用未插桩的源码，故障点和规则都不进入出题的代码、镜像和数据。

### 6.1 Python 改写器（`faultpoint rewrite`）

在标准库 `ast` 上改写源码副本，用 `ast.unparse` 输出。

- `branch`：主体中直接含有 `raise <异常>` 的 `if`，条件改为 `faultpoint.points.branch(id, 条件)`。
- `check`：返回注解为 `bool` 的函数，每个 `return` 改为 `faultpoint.points.check(id, 值)`；所有返回值都是常量时跳过。
- `loop`：在 `for`、`while` 循环体的开头插入 `faultpoint.points.loop(id)`；`for _ in range(<常量>)` 跳过。
- `clock`：`time.time()`、`datetime.now()`、`datetime.utcnow()` 包装为 `faultpoint.points.clock(id, ...)`。
- 局限：Python 没有类型信息，`check` 依赖返回注解，`clock` 依赖调用名。“库函数在调用点抛出的异常”需要知道被调函数会抛出什么，第一版不支持。

### 6.2 Go 改写器（`fprewrite`）

用 `golang.org/x/tools/go/packages` 加载带类型信息的语法树，再用 `go/format` 输出。

- `call`：条件为 `err != nil`、且 `err` 的类型是 `error` 时，改为 `faultpoint.Failed(ctx, id, &err)`：观测 err，注入时替换它。之所以替换 err 本身、而不是强制进入分支，是因为 err 为 nil 时强行进入分支，返回的仍是 nil 错误。
- `branch`：主体中直接返回非 nil 错误的其他 `if`，条件改为 `faultpoint.Branch(ctx, id, 条件)`。
- `check`：唯一结果为 `bool` 的函数，包装每个 `return`；所有返回值都是常量时跳过。
- `loop`：在循环体开头插入 `faultpoint.Loop(ctx, id)`；上界为常量的三段式 `for` 循环跳过。
- `clock`：类型检查确认为 `time.Now` 的调用，包装为 `faultpoint.Clock(ctx, id, time.Now())`。
- 错误登记：为每个含有包级 `error` 变量的包生成 `faultpoint_errors.go`，在 `init` 中调用 `faultpoint.RegisterError`。
- `go.mod` 中加入对 SDK 的 `require` 和指向本地路径的 `replace`。

### 6.3 Java（规划中）

用 ASM 在构建期改写字节码：`branch` 放在守卫 `athrow` 的条件跳转上，`call` 放在声明了受检异常的调用点上，`check` 放在 `boolean` 方法的返回处，`loop` 放在回边上。边界用 Servlet Filter、HTTP 客户端拦截器和 JDBC 代理实现。上下文使用 OpenTelemetry 的 `Context` 和 `Baggage`。

## 7. 运行时

| 环境变量 | 含义 | 缺省 |
| --- | --- | --- |
| `FAULTPOINT_SERVICE` | 服务名，用于边界故障点的 id 和观测记录 | 必填（启用时） |
| `FAULTPOINT_RULES` | 规则文件路径 | 不注入 |
| `FAULTPOINT_REPORT` | 观测输出路径 | 不观测 |
| `FAULTPOINT_SCOPE_KEY` | 作为观测范围的 baggage 键 | `fp.scope` |
| `FAULTPOINT_FLUSH_SECONDS` | 观测写出的间隔 | 2 |
| `FAULTPOINT_SEED` | 概率触发的随机种子 | 0 |

- 规则和观测都未配置时，每个故障点只读一个全局标志就返回。
- 延迟有两种语义。边界上的延迟表示对端变慢，异步代码中不阻塞事件循环。进程内的延迟表示资源竞争，会阻塞当前线程。
- `crash` 先写出观测，再以指定的退出码立即终止进程。
- 进程被强制杀死时，最后一个间隔内的观测会丢失，所以收集观测前要等待至少两个写出间隔。

## 8. 反事实比较（`faultpoint diff`）

对照组和处理组各由若干次重复组成，每次重复用（实验，范围）选出。对每个（故障点，outcome）：

- 计数在对照的每次重复中都为 0、在处理的每次重复中都大于 0 时，记为 `new`；
- 否则，若处理组的计数或每次执行的平均 total 显著大于对照组（单侧 Welch t 检验，默认 p<0.1），记为 `increase`；
- 处理组中带有规则 id 的记录是注入本身，单独列出以确认规则确实触发了，不计入效果。

## 9. 各语言的实现状态

| 部分 | Python | Go | Java |
| --- | --- | --- | --- |
| 规则、观测、运行时 | 已实现 | 已实现 | 规划中 |
| 进程内 API | `branch` `check` `loop` `value` `clock` `acquire` | 同左，另有 `call`（`Failed`） | 规划中 |
| HTTP 边界 | ASGI 中间件、httpx 异步客户端 | `net/http` 中间件和 `RoundTripper` | 规划中 |
| SQL 边界 | DB-API 2 连接包装 | `database/sql` 驱动包装 | 规划中 |
| 消息边界 | 规划中 | 规划中 | 规划中 |
| 改写器 | `branch` `check` `loop` `clock` | `call` `branch` `check` `loop` `clock`，以及错误登记 | 规划中 |
