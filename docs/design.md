# faultpoint 设计

faultpoint 在被测系统的代码中放置故障点。同一个故障点既能按规则注入故障，也能在故障自然发生时上报观测，因此一次注入实验引起的“额外故障”可以用与注入相同的词汇表达，为反事实的因果边发现提供数据。

本仓库只负责故障点本身：类别、身份、规则、观测与接入。实验编排、因果边的统计、拼接搜索和落地成题由使用它的搜索系统负责；`faultpoint diff` 只提供一次反事实比较的参考实现。

故障点覆盖三层，三层用同一套规则和观测格式，链路才能跨层拼接：

| 层 | 内容 | 接入方式 |
| --- | --- | --- |
| 业务代码 | 服务自己的代码 | 各语言 SDK 的启动钩子或构建副本（第 6.2 节） |
| 依赖库 | 服务链接或导入的第三方库 | 托管语言的库：同样的启动钩子扩大范围；Go、Rust 的库：构建期替换（第 6.4 节）；原生 C 库（libc、OpenSSL、libpq 等）：eBPF uprobe 或用户态 eBPF |
| 供应链上游组件 | 独立运行的基础设施，例如 Redis、PostgreSQL、消息中间件 | 组件内部函数：eBPF uprobe 或用户态 eBPF；组件所在容器的系统调用与网络包：eBPF 代理 |

## 0. 架构：核心与插件

两条原则：

- **轻量**：每种语言的 SDK 只有一个很小的核心，其余能力都是插件，按需加载。
- **不写死**：类别、动作、观测结果、放置规则和输出方式，都来自共享的数据文件或配置，而不是写在各语言的代码里。

| 层 | 职责 | 不负责 |
| --- | --- | --- |
| 核心 | 通过规则来源取得规则集；按故障点 id、范围和触发条件选出规则（`decide`）；把观测交给观测输出（`observe`）；通过上下文提供者读取 baggage 和 trace id；维护插件的登记 | 任何类别的语义、类别与动作的对应表、观测结果的词汇、库适配、放置规则、分析 |
| 故障点插件 | 一个类别的语义：在故障点上执行动作，报告 outcome。登记时声明自己服务哪些类别、实现哪些动作 | 规则匹配 |
| 边界适配插件 | 把某个库或框架（httpx、ASGI、DB-API、`net/http`、`database/sql`、undici、Servlet、JDBC、tower……）的调用变成边界类故障点，选项（路径模板、语句分类）可配置 | 接入方式 |
| 接入插件 | 把故障点和适配器装进进程或构建：Python 导入钩子、Node 加载钩子、Java agent、Go/Rust 构建副本改写器 | 规则与观测 |
| 规则来源 | 缺省为轮询本地文件；可替换为 HTTP、ConfigMap 等 | — |
| 观测输出 | 缺省为 JSON Lines 文件，写出间隔和样例数是它的选项；可替换为 OpenTelemetry 指标、标准输出等 | — |
| 上下文提供者 | 缺省读取 OpenTelemetry 的 baggage 和 trace context | — |
| eBPF 代理 | 独立进程，承担 `syscall` 与 `packet` 两类故障点，使用同样的规则来源和观测输出约定 | 请求级范围 |
| 工具 | `check`（按 `spec/kinds.json` 校验规则集）、`scan`（离线生成清单）、`diff`（反事实比较），不进入被测进程 | — |

- **类别表是数据**：`spec/kinds.json` 是类别、动作及其参数约束的唯一来源。各语言的核心只校验规则集的通用结构：实验名、规则 id 不重复、故障点 id 的形状、触发条件的取值范围。动作参数是一个自由对象，由执行它的插件解释。控制方安装规则前，先用 `faultpoint check` 按 `spec/kinds.json` 完整校验一遍。
- **加载时的适用性检查**：规则集加载时，核心对属于本服务、且本进程登记了对应类别插件的规则，检查其动作是否被本进程中**每一个**服务该类别的插件接受（取交集），否则判定规则集无效。这样，一个类别由多个插件服务时（例如 SQL 驱动与 pgx 都服务 `store_read`），不适用的规则在加载时就被拒绝，而不是运行到某个故障点才中止。本进程没有登记的类别，规则留给其他进程（例如 eBPF 代理），核心忽略它们。
- **插件的发现**：按各语言的惯例。Python 用入口点（entry points），Node 用包名动态导入，Java 用 `ServiceLoader`，Go 和 Rust 在编译期登记（`init` 或链接期收集）。启用哪些插件、各自的选项，由配置决定（见第 7 节）。

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
| 系统调用：`syscall` | `fail`（errno） | — | — | — | — | — |
| 网络包：`packet` | `drop` | `delay` | — | — | — | — |
| 进程生命周期 | `crash`（除 `packet` 外的故障点都可执行） | | | | | |

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

下表是 `spec/kinds.json` 的说明；两者不一致时，以 `spec/kinds.json` 为准。

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
| `publish` | 消息生产 | `fail` `delay` `fail_after` `drop` `duplicate` | `ok` `error` |
| `consume` | 消息消费 | `fail` `delay` `fail_after` `duplicate` `empty`（取不到消息） | `rows` `empty` `error`，消息条数记入 total |
| `syscall` | 进程的系统调用（eBPF） | `fail`：返回指定的 errno | `ok`，或 errno 名 |
| `packet` | 容器网络接口上的包（eBPF） | `delay` `drop` | `delayed` `dropped` |

除 `syscall` 和 `packet` 外，所有类别都还可以执行 `delay` 和 `crash`。`syscall` 不能延迟，因为 eBPF 程序不能在内核探针里睡眠；它可以执行 `crash`：eBPF 程序在系统调用入口向进程发送 SIGKILL，系统调用照常执行，进程在返回用户态时终止，退出状态总是 137，规则中的 `code` 不起作用。`packet` 只作用于网络包，不针对某个进程，因此没有 `crash`。值错误中，只有布尔取反（`negate`）由插桩自动放置；一般的业务计算错误空间大、误报多，因此 `value` 只放在人工标注的、在业务约束上有意义的计算上（金额、配额、时间窗口、版本号），并且只在合法值域内扰动。

### 1.4 完整性检查

类别表的完整性无法证明，只能对照检查。每遇到一个已知案例（公开的故障研究、已有题目），逐跳检查是否能用上表的某一格表达；表达不了的一跳，说明缺少一个类别或动作。

## 2. 故障点的身份

故障点 id 的格式为 `<service>:<kind>:<locator>`，类别是 id 的一部分，所以规则加载时就能检查动作是否适用。

| 来源 | locator |
| --- | --- |
| 改写器放置的进程内故障点 | `<相对路径>:<函数限定名>#<锚点>`，`check` 每个函数一个，省略锚点 |
| HTTP 边界 | `<METHOD> <路径模板>`，客户端前面再加对端主机；路径中的数字、UUID 和长十六进制段替换为 `{}` |
| SQL 边界 | `<表名，以 + 连接>#<规范化语句的哈希>` |
| 系统调用 | 系统调用名，例如 `connect` `read` `write` `fsync` |
| 网络包 | `<egress 或 ingress>:<对端 IP 或 *>:<对端端口或 *>`。`egress` 是服务的容器发出的包，按目的地址匹配；`ingress` 是它们收到的包，按源地址匹配。端口取最后一个 `:` 之后的部分，所以 IPv6 地址保留其中的冒号 |

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

- **范围**：`scope` 中的每一项都必须等于当前请求 baggage 中的同名项，规则才生效。不在任何请求中的后台工作没有 baggage，只匹配 `scope` 为空的规则。内核看不到请求的 baggage，所以 `syscall` 和 `packet` 的规则不能带 `scope`，作用范围就是故障点所属服务的所有容器。
- **触发**：每个进程对每条规则单独计数：先跳过前 `skip` 次匹配，之后最多注入 `limit` 次，每次以 `probability` 的概率注入（随机数以 `FAULTPOINT_SEED` 和规则 id 为种子）。并发下“第 n 次”本身是不确定的，所以优先用 `scope` 限定到具体的租户或请求，少用计数。`syscall` 和 `packet` 的计数由 eBPF 代理在内核中进行，范围是一条规则在该服务所有容器上的匹配，而不是每个进程；它的随机序列与各语言 SDK 的不同。
- **适用性**：动作必须属于该类别的可用动作（见 1.3）。边界类故障点的 `fail` 和 `fail_after` 用 `status` 指定合成的响应状态，或用 `error` 指定 `timeout` 或 `refused`。`call` 的 `error` 是已登记的错误名，Go 改写器会把包级的 `error` 变量自动登记为 `<包路径>.<变量名>`，这样注入的就是代码真实会返回的哨兵错误。`syscall` 的 `fail` 必须给出 errno 名，例如 `ECONNREFUSED`。
- **原子更新**：控制方先写临时文件再改名替换。缺省的文件规则来源每 0.5 秒检查一次修改时间。核心在换上新规则集之前，先让观测输出写出当前的计数，因此每条观测记录只属于一个实验。规则集无效时，核心终止进程，以免实验在无效的规则下继续运行。

## 4. 观测

故障点每被执行一次，就记录一个结果。核心把结果交给观测输出。缺省的观测输出在进程内按（实验，故障点，outcome，范围，注入规则）聚合成计数和 total，定期以 JSON Lines 的形式追加到 `FAULTPOINT_REPORT`，格式由 `spec/observation.schema.json` 定义。其他观测输出必须保留同样的字段，`diff` 才能读取。

- **范围**：取 baggage 中 `FAULTPOINT_SCOPE_KEY`（默认 `fp.scope`）的值，用于在同一次部署中区分被注入的请求与作为对照的请求。
- **注入规则**：被注入的那次执行，记录中带有规则 id；自然发生的执行，这一项为空。比较时可以把注入本身和它引起的效果分开。
- **样例**：当前上下文中有有效的 trace 时，每个键保留若干个 trace id（缺省 5 个，是观测输出的选项），用于把效果追溯到具体请求。
- **独立管道**：观测写入单独的文件，不进入被测系统的日志、追踪和指标，避免进入诊断者可以申请的数据。
- **细节**：outcome 只是一个粗的类别，同一个 outcome 之后可能发生截然不同的事。因此每条记录还带一个 `detail`：一个键和值都是字符串的映射，属于聚合键的一部分。每个类别有哪些键，由 `spec/kinds.json` 中该类别的 `details` 给出，各键的含义如下：
  - `status`：精确的状态码，例如 `409`。
  - `error`：错误或异常的类型名，例如 Python 的带模块路径的类名、Go 已登记的哨兵名（不是哨兵时用类型名）、Java 的类全名、Node 的 `error.code` 或 `error.name`、Rust 的类型名。
  - `sent`：客户端失败时请求是否已完整发出（`true`/`false`），用来区分“对方可能已经做了”与“对方没有收到”。
  - `abandoned`：服务端写响应时客户端是否已经离开（`true`/`false`），用来识别“工作在调用方超时之后才完成或失败”。
  - `code`：存储返回的错误码，例如 SQLSTATE，或 Redis 错误回复的前缀。
  - `value`：原生函数返回的整数值。
  `sent` 只出现在客户端失败的记录上，成功的回复只带 `status`；`abandoned` 出现在每一条服务端记录上，取 `true` 或 `false`。被注入的执行也带上它产生的细节，例如注入 `fail` 且 `status=503` 时记 `status=503`，注入异常时记所抛出的类型。这样，拼接时可以用细节相同的故障替代上一跳自然产生的结果。键的取值必须有界：不放消息文本、标识符或时间。
- **内核故障点**：eBPF 代理只观测配置中列出的系统调用，在它们的 `syscalls:sys_exit_<name>` 跟踪点上计数，因此对照组和处理组观测的是同一组系统调用。被注入的执行只记在规则 id 下，不计入自然结果。没有用户态名字的内核 errno（如 `ERESTARTSYS`）记为 `errno <数值>`。这类记录的范围总为空，没有样例。网络包只观测被注入的结果（`delayed` `dropped`），自然丢包没有观测。

## 5. 上下文

请求上下文使用 OpenTelemetry 的 W3C baggage 和 traceparent。

- 已经接入 OpenTelemetry 的系统，由它原有的插桩负责跨服务传递。SDK 只读取上下文，不依赖 OpenTelemetry SDK。
- 没有接入的系统，由本仓库的 HTTP 边界适配器负责提取和注入这两个请求头。
- Python 的上下文基于 contextvars，能随协程和线程池传递。Node 使用 OpenTelemetry 基于 AsyncLocalStorage 的上下文管理器；进程尚未登记上下文管理器时，由 SDK 登记。Java 使用 OpenTelemetry API 的 `Context`。Rust 使用 `opentelemetry::Context`，服务端适配器用 `with_context` 把上下文挂到请求的 future 上。
- Go 必须显式传递 `context.Context`。改写器使用所在函数的 `context.Context` 参数或 `*http.Request` 参数的 `Context()`；找不到时传入 `nil`，这时故障点只匹配 `scope` 为空的规则，观测的范围为空。

## 6. 接入方式

**原则**：业务源码和线上构建都不包含 SDK。解释型和 JIT 语言只通过启动参数或环境变量接入；编译型语言只在构建副本中接入。没有这些参数、不用构建副本时，服务与 SDK 无关。

### 6.1 调研：几种低侵入方式的能力与限制

| 方式 | 改动范围 | 能做的 | 做不到的 |
| --- | --- | --- | --- |
| eBPF kprobe 覆盖返回值 | 不改代码和构建；需要加载 eBPF 的特权 | 任意语言进程的系统调用返回指定 errno（`bpf_override_return`，要求 `CONFIG_BPF_KPROBE_OVERRIDE`，且函数在错误注入白名单中，系统调用在其中），可按 cgroup 限定到容器 | 不能延迟（探针里不能睡眠）；看不到请求的 baggage |
| eBPF tc 程序 | 同上 | 按对端地址和端口丢包；把 `skb->tstamp` 设为将来时刻，再由 fq qdisc 按时发送，实现延迟（EDT） | 看不到请求；接口上需要 fq qdisc |
| eBPF uprobe 写寄存器 | 同上；内核 6.18 起支持 | 编译型语言中，在未被内联、通过 call 调用、返回整型或布尔的函数入口直接返回指定值 | 解释型和 JIT 语言（Python、Node、Java）无法按源码函数定位；Go 不能用 uretprobe（会和栈搬迁冲突），观测自然返回值要在每条 ret 指令处放 uprobe；被内联的函数没有入口；返回 error 接口或 `Result` 需要在用户内存中构造值 |
| 语言运行时钩子 | 只改启动参数或环境变量 | 请求级范围、语义级故障点、库边界 | 需要运行时提供钩子 |
| 编译期改写（构建副本、Go 的 `-toolexec`） | 只改构建流程 | 同上，并有完整的类型信息 | 需要重新构建 |
| 服务网格（Envoy 故障过滤器） | 只改部署 | HTTP 拒绝和延迟，可按请求头（包括 baggage）匹配 | 不支持 `fail_after` 和 `duplicate`；需要部署网格 |
| 用户态 eBPF（bpftime） | 只改环境变量（`LD_PRELOAD`），对原生库不需要 root | 在 Python、Node、JVM、Rust 进程的原生 C 库函数上观测与覆盖返回值，每次命中比内核 uprobe 便宜约 5–6 倍 | 同一函数上的覆盖与返回观测互斥；覆盖标记按钩子而不按线程保存，多线程下注入次数不准；Go 函数会使运行时崩溃；系统调用钩子需要 `CAP_SYS_RAWIO`；延迟只能忙等 |

**结论**：请求级、语义级的故障点由语言运行时钩子承担，编译型语言改用构建副本；与请求无关的环境故障（系统调用、网络包）由 eBPF 代理承担；原生函数和上游组件中的故障点由内核 uprobe 承担（第 6.5 节）。用户态 eBPF 因为同一函数不能既注入又观测、多线程下注入不准，不满足故障点的基本要求，暂不采用；它可以作为不需要特权的“只观测”选项，前提是先修正这两点。服务网格可以替代 RPC 边界的一部分，第一版不实现。

参考：[bpf_override_return](https://docs.ebpf.io/linux/helper-function/bpf_override_return/)、[Tetragon 的 uprobe Override 条件](https://tetragon.io/docs/concepts/tracing-policy/selectors/)、[Node `module.registerHooks`](https://nodejs.org/api/module.html)、[OpenTelemetry Go 编译期插桩](https://opentelemetry.io/docs/zero-code/go/compile-time/)、[Cargo 的 rustc 包装器](https://doc.rust-lang.org/cargo/reference/config.html)。

### 6.2 各语言的接入

| 语言 | 接入点 | 进程内故障点 | 边界 |
| --- | --- | --- | --- |
| Python | `PYTHONPATH` 指向 SDK 的引导目录，其中的 `sitecustomize` 在启用时安装插件，并链式调用原有的 `sitecustomize`；SDK 须安装在服务的环境中，因为插件经入口点发现 | 导入钩子改写 `FAULTPOINT_SOURCE_ROOT` 下的模块，不读写字节码缓存 | 在应用导入相应的库时才打补丁：httpx 补在 `HTTPTransport.handle_request` 和 `AsyncHTTPTransport.handle_async_request`；ASGI 补在 uvicorn 的 `Config.load` 解析出的应用上，因此只覆盖由 uvicorn（包括 gunicorn 的 UvicornWorker）运行的 ASGI 应用；DB-API 补在 `sqlite3.connect`，其他驱动可用通用包装 |
| Node / TypeScript | `NODE_OPTIONS=--import faultpoint/register` | `module.registerHooks` 的 `load` 钩子同步改写 `FAULTPOINT_SOURCE_ROOT` 下、`node_modules` 以外的 JS 和 `placement.scope` 列出的包，对 `require` 和 `import` 都生效（Node 22.15 起） | 补丁 `http.Server.prototype.emit` 的 `request` 事件；包装全局 `fetch`；补丁 `http.request` 和 `https.request`，其中 `duplicate` 无法重发请求体，遇到时以规则 id 和原因终止进程；补丁应用所解析到的 pg 的 `Client.prototype.query` 和 ioredis 的 `sendCommand`，连接池和客户端替应用发出的语句与命令也经过故障点 |
| Java | `JAVA_TOOL_OPTIONS=-javaagent:faultpoint-agent.jar` | ASM 改写 `FAULTPOINT_PACKAGES` 下的类和 `placement.scope` 列出的包前缀；`loop` 放在每条回跳指令之前，按完成的迭代计数；放置先于边界的 advice 登记，所以看到的是类的原始字节，与离线 `scan` 一致 | ByteBuddy 内联 advice，advice 类不由 agent 装载，所以库在子类加载器中（Spring Boot、Tomcat）时也能解析：Servlet 的 `HttpServlet.service`，`java.sql.Statement` 各实现的 `execute*`（`Connection.prepareStatement` 记下语句文本），Spring 的 `ClientHttpRequest.execute`，Lettuce 的 `RedisChannelHandler.dispatch`；JDK 的 `HttpClient.send` `sendAsync` 不能加 advice，改为把业务代码中的调用改成调用 SDK 的静态方法 |
| Go | 构建流程中先运行 `fprewrite instrument`，在副本上构建；`fprewrite scan` 用同一个放置实现只写清单 | 带类型信息的改写器 | 改写器在副本中包装传给 `ListenAndServe` `ListenAndServeTLS` `Serve` `ServeTLS` 的 handler，键值字面量和字段赋值中 `http.Server` 的 `Handler` 与 `http.Client` 的 `Transport`（缺省的字段补为包装后的缺省值），`sql.Open` 的驱动名；在每个 main 包中生成一个文件，包装 `http.DefaultClient` 并在所有插件登记后启动核心。不替换 `http.DefaultTransport`，因为代码中对它的 `*http.Transport` 类型断言会失败 |
| Rust | 构建流程中先运行改写器（`syn`），在副本上构建 | 语法改写器；`call` 只放在返回 `anyhow::Result` 或 `Box<dyn Error>` 的函数中，因为注入需要 `From<Injected>`；宏的参数（如 `format!`、`tracing` 的宏）不被改写，因为 `syn` 不解析宏内的记号；`const fn` 不放置 | 在 `axum::serve` 的调用处挂 tower 层；把 `sqlx::query*(…).fetch_*/execute(…)` 和 `redis::cmd(…)….query_async(…)` 调用链改写为经过 SDK 的调用，注入用的错误和替代值由调用处按应用自己的类型构造；请求级的 `rpc_client` 不支持，因为 reqwest 不改客户端类型就没有请求级钩子，连接级的故障由 eBPF 承担 |
| 任意语言 | eBPF 代理以特权进程运行（需要 `--privileged`、`--cgroupns=host`、tracefs 和容器网络命名空间的路径），按服务对应的 cgroup 生效 | — | `syscall`：kprobe 挂在 `__x64_sys_<name>`（或 `__arm64_sys_`）上，用 `bpf_override_return` 返回 `-errno`。`packet`：tcx 程序总是挂在设备的发送方向上，因为 EDT 延迟只在发送方向由 fq 执行：容器发出的包在容器网络命名空间内的网卡上处理，容器收到的包在其虚拟网线的宿主机一端上处理，因此两个方向都支持延迟。fq 只装在有延迟规则的设备上，并且只替换内核缺省的根 qdisc |

- Rust 不用 `RUSTC_WORKSPACE_WRAPPER`：SDK 的 crate 必须和应用的 tower、http 版本由 cargo 一起解析，所以只能在副本的 `Cargo.toml` 中加依赖。
- Go 不用 `-toolexec` 改写标准库：把 SDK 导入 `net/http` 会形成导入环（SDK 依赖 OpenTelemetry，后者依赖 `net/http`）。
- 运行时接入（Python、Node、Java）在装载时改写，但故障点的 id 必须与离线 `scan` 生成的清单一致，所以两者使用同一个放置实现，路径都相对于 `FAULTPOINT_SOURCE_ROOT`。
- Node 包装全局 `fetch`，不用 undici 全局 dispatcher 的拦截器：对使用 `fetch` 的代码覆盖相同，又不依赖 undici 的处理器接口版本。直接使用 undici 的代码不被覆盖。
- **已知缺口（Go）**：改写器只改写服务模块自己的包，依赖内部创建的服务端和客户端（例如 gin 的 `Run`、第三方 SDK 的客户端）不被装配；`new(http.Client)`、零值客户端、按位置书写的字面量和 `sql.OpenDB` 也不被装配。所在函数没有 `context.Context` 或 `*http.Request` 时，故障点只匹配不带范围的规则。
- **已知缺口（eBPF）**：容器重启后 cgroup、网络命名空间和虚拟网线都会变化，需要更新配置并重启代理；32 位兼容系统调用（`__ia32_sys_`）不被覆盖；延迟须小于 fq 的时间窗（10 秒）；只有内核缺省根 qdisc 的设备才能设延迟。
- **已知缺口（Java）**：Spring 的 `WebClient`（`ExchangeFunction.exchange`）、`feign.Client.execute`、Apache HttpClient 与 OkHttp 的执行入口还没有 advice；Lettuce 和 Spring 客户端不支持 `fail_after` 和 `duplicate`，因为回复已交给调用方或请求体已被消费；经 `Statement.execute` 发出的读操作，只要有结果集就记为 `rows`，不数其中的行，因为结果集由调用方随后另取。
- **已知缺口（Node）**：ioredis 不支持 `fail_after` 和 `duplicate`；只覆盖应用自己解析到的 pg 和 ioredis 实例，其他包各自安装的副本不被补丁。
- **已知缺口（Rust）**：只改写调用链形式的 sqlx 和 redis-rs 调用，`query!` 等宏与 `AsyncCommands` 的类型化方法不被改写；redis 读命令只有注入的 `empty` 记为 `empty`，自然的空回复记为 `rows`，因为回复的类型由调用处决定；被丢弃的 redis 写命令以状态回复 `OK` 代替，调用处要求数字回复时会变成错误。依赖 crate 的副本放在副本的 `faultpoint-scope/` 下，依赖图中同名 crate 有多个版本时改写器报错退出，因为 `[patch.crates-io]` 每个名字只能替换一个版本。

### 6.3 放置规则

各语言的放置规则形式相同。每条规则都可以在配置中关闭，规则中的名单（例如读时钟的函数）可以在配置中替换：

- `branch`：直接守卫抛出异常或返回非 nil 错误的条件判断，条件改为 `branch(id, 条件)`。
- `call`：Go 中类型为 `error` 的 `err != nil`，改为 `Failed(ctx, id, &err)`，观测 err，注入时替换它。替换 err 而不是强制进入分支，是因为 err 为 nil 时强行进入分支，返回的仍是 nil 错误。
- `check`：返回布尔值的函数，包装每个 `return`；所有返回值都是常量时跳过。有类型信息的语言按类型判断，Python 按返回注解判断，JS 按返回表达式的形状判断。
- `loop`：在循环体开头插入 `loop(id)`；上界为常量的循环跳过。
- `clock`：读当前时间的调用（缺省名单：Python 的 `time.time` `datetime.now` `datetime.utcnow`，Go 的 `time.Now`，JS 的 `Date.now` 和无参 `new Date`，Java 的 `System.currentTimeMillis` `Instant.now`，Rust 的 `SystemTime::now` `Instant::now`），包装为 `clock(id, 读数)`。
- Go 为每个含有包级 `error` 变量的包生成登记文件，使 `call` 的 `fail` 能用名字注入真实的哨兵错误。

### 6.4 依赖库中的故障点

连接池、重试、超时、重连、缓存这些传播机制大多在依赖库内部。把放置规则延伸到依赖库，链路就不止于业务代码。延伸有三条约束：接入方式不变，范围和行为由配置限定，先观测、再注入。

**接入方式不变**：各语言沿用自己的接入点，只扩大改写的范围。

| 语言 | 依赖库的改写方式 |
| --- | --- |
| Python | 导入钩子也改写范围内的已安装包；C 扩展内部不放置 |
| Node | 加载钩子也改写范围内的 `node_modules` 包；原生插件内部不放置 |
| Java | agent 也改写范围内的包前缀；`java.*` `jdk.*` `sun.*` 不放置 |
| Go | 含有范围内包的依赖模块各复制一份到构建副本的 `faultpoint-libraries/<模块>@<版本>/`，在副本中改写，再由副本的 `go.work` 或 `go.mod` 用 `replace` 指向它；模块缓存不改。不用 `go build -overlay`，因为 Go 拒绝用它替换模块缓存中的文件。标准库不放置，因为 SDK 依赖标准库，会形成导入环 |
| Rust | 改写后的依赖 crate 副本经副本 `Cargo.toml` 的 `[patch.crates-io]` 替换进构建 |

**范围与行为由配置限定**：配置的 `placement.scope` 列出放置范围，缺省只有业务代码。依赖库须逐个列入，每一项可以限定允许放置的类别：

```json
{"placement": {"scope": [
  {"include": "<业务代码>"},
  {"include": "com.zaxxer.hikari", "kinds": ["branch", "call", "loop", "check"]},
  {"include": "github.com/jackc/pgx/v5/pgxpool", "kinds": ["branch", "call", "loop"]}
], "exclude": ["<SDK 自身>", "<OpenTelemetry>", "<日志库>"]}}
```

- SDK 自身、OpenTelemetry 和日志库始终排除，避免故障点改变观测本身。
- 依赖库的故障点 id 带上库名和版本：`<包或模块>@<版本>/<相对路径>:<函数>#<锚点>`，升级依赖后 id 不会与旧版本混淆。
- 依赖库中的热路径执行次数极多，观测输出对计数保持精确，trace id 样例按配置的比例采样。

**先观测、再注入**：

1. 用扩大后的范围构建或启动，不装任何规则，跑一次对照，得到每个故障点的执行次数。
2. `scan` 生成的清单与这次对照的观测合并，只有实际执行过的故障点才列为注入候选。
3. 可选：再构建一次，只放置候选故障点，以减少开销。

第一步的代价是一次普通的对照运行，能筛掉绝大多数从未执行的故障点。

### 6.5 原生函数中的故障点

原生 C 库（libc、OpenSSL、libpq）、Go/Rust 二进制中的库函数，以及独立运行的上游组件（redis-server、postgres）里的函数，由 eBPF 代理用 uprobe 放置故障点，不改代码、不重新构建。

- **放置**：函数入口挂一个 uprobe，用于注入；函数中每条返回指令再挂一个 uprobe，用于观测自然结果。返回指令通过反汇编函数得到。不使用 uretprobe，因为它与 Go 的栈搬迁冲突，与入口注入同时使用时也不安全。
- **注入**：入口处写入结果寄存器，再模拟返回（从栈上取返回地址写入 ip，并调整 sp），函数体不执行。这要求内核 6.18 及以上，因为更早的内核不允许 uprobe 改写寄存器。返回值可以是常量，也可以是进程内存中某个符号处的值，按入口地址算出加载偏移，因此地址随机化不受影响。Go 的哨兵错误就用这种方式取得真实的接口值。
- **取反**：`check` 需要自然的返回值，所以在每条返回指令处翻转结果寄存器。
- **条件**：可以按入口参数寄存器给出注入条件，例如只在“读查找”时注入，避免破坏组件自身的不变式。注入的值必须在函数真实可能的结果范围内：对 redis-server 写路径上的 `lookupKey` 克隆注入“未找到”，会触发 Redis 自身的断言（`db.c:188`）而使进程退出。
- **符号**：按名字定位并在 id 中带上 build-id。导出符号在去符号的构建中通常仍在（例如 Redis 以 `-rdynamic` 链接），编译器生成的克隆却是局部符号，去符号后就找不到了。导出但从不被调用的函数（例如官方构建中的 `aofWrite`）交给“先观测、再注入”筛掉。
- **配置是数据**：每个原生函数点在代理的配置中给出：文件路径、符号、类别（`call` `check`）、结果寄存器布局、哪种结果算失败、注入时写入的值、注入条件。编译器生成的克隆（`.constprop` `.isra` `.part` `.cold`）一并覆盖。
- **身份**：`<service>:<kind>:<文件名>@<build-id 前 12 位>:<符号>`。
- **范围**：与 `syscall` `packet` 一样，只按服务的 cgroup 限定，规则不能带 `scope`。
- **隔离**：uprobe 挂在文件的 inode 上，共享镜像层中的同一个文件会让所有使用它的容器都陷入，过滤只能阻止注入，不能免去开销。因此目标文件要放在目标容器私有的层里。

**实测的开销与局限**：

- **开销**：每次命中约 0.6–0.8 µs，映射了同一文件的进程都要付出。对 DNS 解析、TLS 读写、连接、整次 HTTP 请求这类调用可以忽略；对热点函数代价很高，例如 redis-server 的 `lookupKey` 在流水线压测下 GET 吞吐下降约 70%。
- **看不到的调用**：被内联的调用看不到；以跳转结束的函数没有返回指令，看不到自然结果。
- **错误由后续调用决定的情形**：例如 OpenSSL 由 `SSL_get_error` 判定，需要成对注入才能得到真实的失败。
- **去符号的 Go 二进制**：可以从 `.gopclntab` 找回函数，但找不到哨兵变量。
- **请求范围**：拿不到。

## 7. 配置与运行时

常用设置用环境变量给出；其余设置都在 `FAULTPOINT_CONFIG` 指向的 JSON 文件里，包括启用哪些插件和各自的选项，以及放置规则的开关与名单。

| 环境变量 | 含义 | 缺省 |
| --- | --- | --- |
| `FAULTPOINT_SERVICE` | 服务名，用于边界故障点的 id 和观测记录 | 必填（启用时） |
| `FAULTPOINT_RULES` | 缺省规则来源读取的文件 | 不注入 |
| `FAULTPOINT_REPORT` | 缺省观测输出写入的文件 | 不观测 |
| `FAULTPOINT_SOURCE_ROOT` | 运行时接入时改写哪些源文件；故障点 id 中的路径相对于它 | 当前目录 |
| `FAULTPOINT_PACKAGES` | Java agent 改写的包前缀，以逗号分隔 | 无（只放边界） |
| `FAULTPOINT_SCOPE_KEY` | 作为观测范围的 baggage 键 | `fp.scope` |
| `FAULTPOINT_SEED` | 概率触发的随机种子 | 0 |
| `FAULTPOINT_CONFIG` | 插件、选项与放置规则 | 只启用缺省插件 |

```json
{
  "plugins": ["points", "import-hook", "httpx", "asgi", "dbapi"],
  "options": {
    "jsonl": {"flush_seconds": 2, "exemplars": 5},
    "httpx": {"identifier_segment": "^(\\d+|[0-9a-f-]{36})$"},
    "dbapi": {"dialect": "sqlite"}
  },
  "placement": {"branch": true, "check": true, "loop": true, "clock": ["time.time", "datetime.now"]}
}
```

- **选项按插件名给出**：每个插件只读取自己名下的选项，缺省组件读取自己的名字（例如 `jsonl`）。一个选项键不对应任何插件或组件时，进程在启动时终止，并在消息中给出这个键。Python 只认配置中启用的插件，Go 认编译进构建的插件。
- **启用哪些插件**：给出 `plugins` 时只启用列出的插件。不给出时，Python 启用缺省集合（`points` `import-hook` `httpx` `asgi` `dbapi`），Go 启用编译进构建的全部插件（改写器缺省编译 `points` `http` `sql`）。
- **放置规则的键**：Go 另有 `call` 和 `errors`（错误登记）两个开关；Go 的读时钟名单使用完整的函数名，例如 `time.Now`。
- **eBPF 代理的选项**在 `ebpf` 名下：`{"services": {"<服务>": {"cgroups": ["/sys/fs/cgroup/..."], "devices": [{"netns": "<网络命名空间路径，空表示代理自己的>", "name": "eth0", "transmits": "egress" 或 "ingress"}]}}, "syscalls": ["connect", ...]}`。代理不使用 `FAULTPOINT_SERVICE`，一个代理进程服务多个服务。
- 规则和观测都未配置时，接入插件不安装任何东西；已经放置的故障点只读一个全局标志就返回。
- 延迟有两种语义。边界上的延迟表示对端变慢，异步代码中不阻塞事件循环。进程内的延迟表示资源竞争，会阻塞当前线程。
- 核心终止进程的所有途径（无效或不适用的规则集、读不到规则文件、`crash` 动作、无效配置）都先写出观测，再按登记顺序运行进程登记的清理，最后退出。eBPF 代理用这个机制在退出前卸下程序、链接和它装上的 fq qdisc；被改写的服务不登记清理。
- 进程被强制杀死时，最后一个间隔内的观测会丢失，所以收集观测前要等待至少两个写出间隔。

## 8. 反事实比较（`faultpoint diff`）

对照组和处理组各由若干次重复组成，每次重复用（实验，范围）选出。对每个（故障点，outcome）：

- 计数在对照的每次重复中都为 0、在处理的每次重复中都大于 0 时，记为 `new`；
- 否则，若处理组的计数或每次执行的平均 total 显著大于对照组（单侧 Welch t 检验，默认 p<0.1），记为 `increase`；平均 total 还须至少比对照组高出一个比例（`min_mean_increase`，缺省 0.2），以免重复次数少时把亚毫秒级的波动判为显著；拼接搜索使用 0.5；
- 处理组中带有规则 id 的记录是注入本身，单独列出以确认规则确实触发了，不计入效果。

## 9. 实现状态

本节记录哪些部分已经按上面的设计实现、哪些还在规划中。

| 部分 | Python | Go | Node / TypeScript | Java | Rust | eBPF 代理 |
| --- | --- | --- | --- | --- | --- | --- |
| 核心与插件结构 | 已实现 | 已实现；核心只依赖标准库 | 已实现 | 已实现 | 已实现 | 已实现，复用 Go 核心 |
| 进程内故障点 | `branch` `check` `loop` `value` `clock` `acquire`，以及在调用点抛出处理器所捕获异常的 `call` | `branch` `call` `check` `loop` `value` `clock` `acquire`，以及错误登记 | `branch` `check` `loop` `value` `clock` `acquire` | 同 Node，另有抛出被调方法所声明受检异常的 `call` | 同 Node，另有 `call` | — |
| 边界适配 | httpx、httpx2、ASGI（uvicorn）、DB-API（sqlite3）、psycopg（含连接池）、redis-py | `net/http`、gin、`database/sql`、pgx（含 pgxpool）、go-redis | HTTP 服务端（含 fastify）、`fetch`、`http.request`、pg、ioredis | Servlet、JDBC 语句实现（覆盖 JdbcTemplate 与 Hikari）、Spring 的 HTTP 客户端、JDK `HttpClient`、Lettuce | tower（axum）、sqlx 与 redis-rs 的调用点 | `syscall`、`packet` |
| 消息边界 | Redis Streams（经 redis-py） | Redis Streams（经 go-redis） | Redis Streams（经 ioredis） | Redis Streams（经 Lettuce） | Redis Streams（经 redis-rs） | — |
| 依赖库中的故障点（第 6.4 节） | 已实现，只改写纯 Python 模块；`faultpoint candidates` 列出执行过的候选 | 已实现，模块副本加 `replace` | 已实现 | 已实现 | 已实现，crate 副本加 `[patch]` | — |
| 原生函数中的故障点（第 6.5 节） | — | — | — | — | — | 只有可行性试验，尚未进入代理 |
| 接入 | 导入钩子 | 构建副本，自动装配边界 | `--import` 加载钩子 | `-javaagent` | 构建副本 | 特权进程 |
| 未覆盖 | 非 uvicorn 运行的 ASGI 应用 | 依赖内部创建的服务端和客户端；pgx 的 `CopyFrom` `Commit` `Rollback` | 直接使用 undici | WebClient、Feign、Apache HttpClient、OkHttp | reqwest、`query!` 宏、类型化的 Redis 命令方法 | 自然丢包、32 位兼容系统调用、IPv6（未验证） |
| 只重放置候选故障点（第 6.4 节第 3 步） | 未实现 | 未实现 | 未实现 | 未实现 | 未实现 | — |
| Kafka、RabbitMQ、NATS | 规划中 | 规划中 | 规划中 | 规划中 | 规划中 | — |
