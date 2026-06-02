# HACK.SKILLS - Agent 的黑客武装

<p align="right"><a href="./README.md">English</a> | 中文</p>

<p align="center">
    <img src="./assets/readme-hero-banner.jpg" alt="HackSkills Hero Banner" width="100%" />
</p>

<p align="center">
    <strong>总入口 → 分类入口 → 深度专题技能</strong><br/>
    一个总入口，六个稳定分类入口，以及 47 个按需下钻的深度专题技能。
</p>

这是一个面向漏洞赏金、Web 安全、API 安全和授权测试的 Agent Skills 知识库。

当前分支已经收敛到标准的目录式结构：每一个 skill 都位于单独目录下，统一采用 `skills/{semantic-identifier}/SKILL.md`。设计目标不是把所有零碎技巧都暴露成入口，而是把 loader 真正需要优先看到的入口压缩为一层总入口、六个分类入口，以及按需下钻的深度专题 skill。

目标很直接：把真正能在实战里派上用场、又方便审查和持续维护的安全知识，整理成一套可安装、可检索、可组合的 HackSkills。

## 知识来源与蒸馏边界

这个仓库不是外部资料的镜像仓库，而是一个面向 Agent 的蒸馏层。

主要参考公开知识来源（仅用于教育性蒸馏）：

| 来源 | 提供的内容 | 蒸馏方式 |
|---|---|---|
| `swisskyrepo/PayloadsAllTheThings` | 64 个漏洞类别、payload 家族、绕过技术、利用链方向 | 蒸馏为场景化索引、方法矩阵、按引擎/按数据库的 payload 分节 |
| `PentesterSpecialDict` | OS 特化 payload 字典、Java 中间件路径 fuzz 列表、文件扩展名数据库 | 蒸馏为参数命名模式、端点频率表、中间件指纹矩阵 |
| `Dictionary-Of-Pentesting` | BugBounty 绕过技巧（12 专题）、云元数据端点、XXE payload 集合、一行命令工具链 | 蒸馏为绕过模式矩阵、云元数据端点表、WAF 厂商绕过分节 |
| `Hello-CTF` | CTF Web 安全教程，含 PHP/Python/Java 实战技巧 | 蒸馏为 CTF 特定技术段落（handler 绕过、filter chain 技巧、Flask PIN 计算） |
| 公开安全研究论文与 CVE 公告 | 方法论框架、漏洞模式分类法、统计分布 | 蒸馏为攻击模式矩阵、系统化测试清单、决策树 |

处理原则：

- 不直接搬运超大字典和长 payload 全集。
- 优先提炼为可路由、可组合、可审查的安全 skill。
- 用小而稳定的样本、分类法和交叉引用来提升 Agent 在真实安全场景中的稳定性。
- 不包含任何特定客户信息，不包含可识别的厂商案例细节，纯教育性方法论。

## 快速开始

首选入口是 `hack`：

```bash
npx skills add yaklang/hack-skills
```

如果你的工具支持直接拉单个 SKILL.md，也可以使用：

- frontmatter name: `hack`
- raw URL: `https://raw.githubusercontent.com/yaklang/hack-skills/main/skills/hack/SKILL.md`

装完以后，推荐顺序很简单：先从总入口开始，再进入分类入口，最后才进入深度专题 skill。

## Loader 优先级

| 层级 | 作用 | 推荐暴露方式 | 代表 skill |
|---|---|---|---|
| 总入口 | 负责全局路由、测试顺序和跨类别切换 | 优先暴露 | [hack](./skills/hack/SKILL.md) |
| 分类入口 | 负责按攻击面分流到稳定的专题族 | 优先暴露 | [recon-for-sec](./skills/recon-for-sec/SKILL.md), [api-sec](./skills/api-sec/SKILL.md), [auth-sec](./skills/auth-sec/SKILL.md) |
| 深度专题 | 提供完整攻击手册和执行细节 | 按需加载 | [xss-cross-site-scripting](./skills/xss-cross-site-scripting/SKILL.md), [sqli-sql-injection](./skills/sqli-sql-injection/SKILL.md) |

## 主要入口

| 类型 | Skill | 用途 | 何时优先使用 |
|---|---|---|---|
| 总入口 | [hack](./skills/hack/SKILL.md) | 全局路由、阶段判断、跨类别切换 | 新目标、未知攻击面 |
| 分类入口 | [recon-for-sec](./skills/recon-for-sec/SKILL.md) | 资产发现、技术识别 | 刚接目标、信息不足 |
| 分类入口 | [api-sec](./skills/api-sec/SKILL.md) | REST、GraphQL、移动端后端路由 | 看到 API 接口 |
| 分类入口 | [auth-sec](./skills/auth-sec/SKILL.md) | 认证、会话、OAuth、JWT、授权 | 看到登录、令牌、对象 ID |
| 分类入口 | [injection-checking](./skills/injection-checking/SKILL.md) | XSS、SQLi、SSRF、XXE、SSTI、CMDi、NoSQL 路由 | 输入进入解释器 |
| 分类入口 | [file-access-vuln](./skills/file-access-vuln/SKILL.md) | 上传、下载、LFI、路径控制 | 文件操作 |
| 分类入口 | [business-logic-vuln](./skills/business-logic-vuln/SKILL.md) | 竞态、价格、流程、状态机 | 业务流程测试 |

## 完整技能索引（47 个技能）

### 侦察与方法论

| 技能 | SKILL.md | SCENARIOS.md | 核心内容 |
|---|---|---|---|
| [hack](./skills/hack/SKILL.md) | 161 行 | - | 总路由器、现象到技能的映射、专家直觉 |
| [recon-for-sec](./skills/recon-for-sec/SKILL.md) | 28 行 | - | 侦察阶段分类路由 |
| [recon-and-methodology](./skills/recon-and-methodology/SKILL.md) | 389 行 | - | 方法论框架、Java 中间件指纹矩阵、泄露检测清单 |

### API 安全

| 技能 | SKILL.md | SCENARIOS.md | 核心内容 |
|---|---|---|---|
| [api-sec](./skills/api-sec/SKILL.md) | 48 行 | - | API 测试分类路由 |
| [api-recon-and-docs](./skills/api-recon-and-docs/SKILL.md) | 60 行 | - | API 发现、OpenAPI/Swagger、隐藏端点 |
| [api-authorization-and-bola](./skills/api-authorization-and-bola/SKILL.md) | 47 行 | - | BOLA/BFLA、批量赋值、对象级授权 |
| [api-auth-and-jwt-abuse](./skills/api-auth-and-jwt-abuse/SKILL.md) | 75 行 | - | JWT 攻击、API 密钥滥用、令牌操控 |
| [graphql-and-hidden-parameters](./skills/graphql-and-hidden-parameters/SKILL.md) | 49 行 | - | GraphQL 内省、批量查询、隐藏参数发现 |

### 认证与授权

| 技能 | SKILL.md | SCENARIOS.md | 核心内容 |
|---|---|---|---|
| [auth-sec](./skills/auth-sec/SKILL.md) | 40 行 | - | 认证测试分类路由 |
| [authbypass-authentication-flaws](./skills/authbypass-authentication-flaws/SKILL.md) | 441 行 | - | 密码重置 22 模式矩阵、验证码绕过 20 方法、不安全随机数（UUID v1/mt_rand/ObjectId） |
| [jwt-oauth-token-attacks](./skills/jwt-oauth-token-attacks/SKILL.md) | 301 行 | - | JWT 算法混淆、密钥混淆、声明篡改、JWKS 滥用 |
| [oauth-oidc-misconfiguration](./skills/oauth-oidc-misconfiguration/SKILL.md) | 45 行 | - | OAuth 流程劫持、OIDC 配置错误 |
| [saml-sso-assertion-attacks](./skills/saml-sso-assertion-attacks/SKILL.md) | 40 行 | - | SAML 断言篡改、SSO 绕过 |
| [idor-broken-object-authorization](./skills/idor-broken-object-authorization/SKILL.md) | 336 行 | - | 8 类系统化 IDOR 测试、ORM 过滤链泄露（Django/Prisma/Ransack） |

### 注入攻击

| 技能 | SKILL.md | SCENARIOS.md | 核心内容 |
|---|---|---|---|
| [injection-checking](./skills/injection-checking/SKILL.md) | 49 行 | - | 注入测试分类路由 |
| [xss-cross-site-scripting](./skills/xss-cross-site-scripting/SKILL.md) | 368 行 | 278 行 | Polyglot payload 库、按厂商 WAF 绕过（Cloudflare/Akamai/Incapsula/WordFence）、CSP 绕过、DOM Clobbering、CSS 注入数据外带 |
| [sqli-sql-injection](./skills/sqli-sql-injection/SKILL.md) | 475 行 | 575 行 | DB2/Cassandra/BigQuery/SQLite 专题、SQLite RCE、WAF 绕过矩阵、CTF 技巧（handler/prepare/innodb） |
| [ssrf-server-side-request-forgery](./skills/ssrf-server-side-request-forgery/SKILL.md) | 314 行 | 226 行 | 云元数据 6 平台矩阵、DNS 重绑定、无头浏览器攻击、Gopher/Redis RCE 链 |
| [ssti-server-side-template-injection](./skills/ssti-server-side-template-injection/SKILL.md) | 340 行 | 319 行 | 15+ 引擎覆盖（Jinja2/Twig/Pug/Handlebars/EJS/Razor/EEx/Smarty）、盲注 SSTI、Flask PIN 计算 |
| [cmdi-command-injection](./skills/cmdi-command-injection/SKILL.md) | 494 行 | - | WAF 绕过（通配符/xor/base64）、PHP disable_functions 6 条绕过路径、组件级 RCE（ImageMagick/FFmpeg/ES） |
| [nosql-injection](./skills/nosql-injection/SKILL.md) | 341 行 | - | 盲注自动化提取脚本、重复键绕过、聚合管道注入、$where JS 执行 |
| [xxe-xml-external-entity](./skills/xxe-xml-external-entity/SKILL.md) | 326 行 | 112 行 | 本地 DTD 注入（Windows/Linux/JAR 17+ 路径）、盲 XXE、Gopher/FTP OOB |
| [deserialization-insecure](./skills/deserialization-insecure/SKILL.md) | 714 行 | - | Java/PHP/Python + Ruby Marshal/YAML 链、.NET BinaryFormatter/ViewState/JSON.NET、Node.js node-serialize/funcster |
| [expression-language-injection](./skills/expression-language-injection/SKILL.md) | 243 行 | - | SpEL、OGNL、Java EL 注入及 RCE 链 |
| [jndi-injection](./skills/jndi-injection/SKILL.md) | 265 行 | - | JNDI/LDAP/RMI 利用、Log4Shell 模式 |
| [crlf-injection](./skills/crlf-injection/SKILL.md) | 175 行 | - | 头注入、HTTP 响应拆分 |
| [request-smuggling](./skills/request-smuggling/SKILL.md) | 298 行 | - | CL.TE/TE.CL/TE.TE 含 8 种混淆变体、HTTP/2 降级走私、客户端去同步 |
| [prototype-pollution](./skills/prototype-pollution/SKILL.md) | 190 行 | - | Express 黑盒探测键、EJS/Kibana Gadget 链、CVE-2019-7609 |
| [type-juggling](./skills/type-juggling/SKILL.md) | 291 行 | - | PHP 松散比较表、Magic Hash（MD5/SHA1/SHA256）、HMAC 0e 暴力、CTF 模式 |
| [http-parameter-pollution](./skills/http-parameter-pollution/SKILL.md) | 208 行 | - | 服务器行为矩阵（9 平台）、HPP+WAF 绕过组合 |
| [xslt-injection](./skills/xslt-injection/SKILL.md) | 281 行 | - | 三条 RCE 链（PHP/Java/.NET）、EXSLT 写文件、Vendor 检测 |
| [csv-formula-injection](./skills/csv-formula-injection/SKILL.md) | 144 行 | - | DDE/rundll32 payload、Google Sheets IMPORT* 外带 |

### 文件与路径攻击

| 技能 | SKILL.md | SCENARIOS.md | 核心内容 |
|---|---|---|---|
| [file-access-vuln](./skills/file-access-vuln/SKILL.md) | 32 行 | - | 文件访问测试分类路由 |
| [path-traversal-lfi](./skills/path-traversal-lfi/SKILL.md) | 603 行 | - | LFI→RCE 7 条路径、PHP Wrapper 矩阵（filter chains/oracle/phar）、pearcmd 四法、参数命名词典 |
| [upload-insecure-files](./skills/upload-insecure-files/SKILL.md) | 287 行 | 158 行 | 成功率公式、编辑器路径矩阵、验证缺陷五维分类、IIS/Apache/Nginx 解析技巧 |

### 业务逻辑与会话

| 技能 | SKILL.md | SCENARIOS.md | 核心内容 |
|---|---|---|---|
| [business-logic-vuln](./skills/business-logic-vuln/SKILL.md) | 32 行 | - | 业务逻辑测试分类路由 |
| [business-logic-vulnerabilities](./skills/business-logic-vulnerabilities/SKILL.md) | 339 行 | 298 行 | 支付篡改矩阵（10 种攻击）、状态机绕过方法论、优惠券/库存竞态 |
| [race-condition](./skills/race-condition/SKILL.md) | 286 行 | - | TOCTOU 模型、HTTP/1.1 末字节同步、HTTP/2 单包攻击、Turbo Intruder 模板、CVE-2022-4037 |
| [csrf-cross-site-request-forgery](./skills/csrf-cross-site-request-forgery/SKILL.md) | 324 行 | - | JSON CSRF 三种技术、Multipart 上传 CSRF、CSPT2CSRF 现代变体 |
| [clickjacking](./skills/clickjacking/SKILL.md) | 163 行 | - | 基于 Frame 的攻击、X-Frame-Options/CSP 绕过 |
| [cors-cross-origin-misconfiguration](./skills/cors-cross-origin-misconfiguration/SKILL.md) | 50 行 | 152 行 | Origin 反射、null origin、子域信任滥用 |
| [open-redirect](./skills/open-redirect/SKILL.md) | 184 行 | - | 重定向链滥用、Tabnabbing（反向标签劫持） |
| [web-cache-deception](./skills/web-cache-deception/SKILL.md) | 211 行 | - | 路径混淆、缓存键操控 |

### 基础设施与供应链

| 技能 | SKILL.md | SCENARIOS.md | 核心内容 |
|---|---|---|---|
| [unauthorized-access-common-services](./skills/unauthorized-access-common-services/SKILL.md) | 380 行 | - | 服务暴露清单、反向代理配置错误（Nginx off-by-slash、X-Forwarded-For 信任、Caddy 模板注入） |
| [insecure-source-code-management](./skills/insecure-source-code-management/SKILL.md) | 161 行 | - | .git/.svn/.hg/.bzr 恢复、403 vs 404 检测、备份文件模式 |
| [dependency-confusion](./skills/dependency-confusion/SKILL.md) | 178 行 | - | npm/pip/gem 公共注册表劫持、清单识别、scope/namespace 防御 |
| [websocket-security](./skills/websocket-security/SKILL.md) | 146 行 | - | CSWSH、Origin 验证、wsrepl/ws-harness 工具链 |

### 合计：47 个 SKILL.md 文件 + 8 个 SCENARIOS.md 文件 = 55 篇文档，约 14,000 行

## 技能选择建议

| 现象 | 推荐入口 | 说明 |
|---|---|---|
| 新目标、信息不足 | [recon-for-sec](./skills/recon-for-sec/SKILL.md) | 先做方法论和资产理解 |
| REST API、GraphQL、移动端后端 | [api-sec](./skills/api-sec/SKILL.md) | 先分流到 recon、authz、token 或 GraphQL |
| 登录、重置密码、2FA、JWT、OAuth | [auth-sec](./skills/auth-sec/SKILL.md) | 先分认证、授权、协议配置 |
| HTML/JS 反射、模板表达式 | [injection-checking](./skills/injection-checking/SKILL.md) | 先确定 XSS、SQLi、SSRF、XXE 还是 SSTI |
| 文件路径、下载接口、上传链路 | [file-access-vuln](./skills/file-access-vuln/SKILL.md) | 先分 LFI/Traversal 与 Upload |
| 优惠券、支付、状态机 | [business-logic-vuln](./skills/business-logic-vuln/SKILL.md) | 先按业务规则和竞态建模 |
| HTTP 请求解析异常 | [request-smuggling](./skills/request-smuggling/SKILL.md) | 前后端分帧不一致 |
| Node.js `__proto__` 可控 | [prototype-pollution](./skills/prototype-pollution/SKILL.md) | 客户端 PP→XSS、服务端 PP→RCE |
| PHP 弱比较、0e hash | [type-juggling](./skills/type-juggling/SKILL.md) | 松散比较认证绕过 |
| .git/.svn/.env 路径可访问 | [insecure-source-code-management](./skills/insecure-source-code-management/SKILL.md) | 源码恢复 |
| 内部包名出现在清单文件中 | [dependency-confusion](./skills/dependency-confusion/SKILL.md) | 供应链劫持 |
| WebSocket 协议升级 | [websocket-security](./skills/websocket-security/SKILL.md) | CSWSH 和 WS 注入 |
| CSV/Excel 导出功能 | [csv-formula-injection](./skills/csv-formula-injection/SKILL.md) | 导出中的 DDE 注入 |
| 一次性操作（优惠券、奖励） | [race-condition](./skills/race-condition/SKILL.md) | 并发请求突破限额 |

## 安装方式

### 通用安装

```bash
npx skills add yaklang/hack-skills
```

### Raw URL 安装

```bash
curl -fsSL https://raw.githubusercontent.com/yaklang/hack-skills/main/skills/hack/SKILL.md
```

### 本地作为知识库使用

```bash
git clone https://github.com/yaklang/hack-skills.git
cd hack-skills
```

## 设计原则

- 安全知识优先于花哨包装。
- 内容可审查性优先于数量扩张。
- 优先服务授权测试、合法研究与防御验证场景。
- 目录名尽量让人一眼看出安全语义。
- 不包含任何特定客户信息；所有内容均为通用教育性方法论。

## 贡献方式

欢迎提交 PR，重点方向包括：

- 新漏洞类别与高价值案例
- 更好的漏洞赏金方法论
- Agent 容易忽略的边界条件
- 风险提示、术语统一与内容去噪

贡献内容建议满足：可验证、可审查、不鼓励未授权攻击、能帮助 Agent 在真实任务中更稳健地推理与执行。
