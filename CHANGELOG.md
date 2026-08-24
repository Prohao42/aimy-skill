# Changelog

## [3.7.0] - SRC 批量资产实战化：4 大新命令 + 全量修复
### 新增
- `unauth` 命令 + tools/unauth_scan.py：未授权中间件批量检测（Redis/ES/Mongo/MySQL/Postgres）+ 回显型蜜罐自动识别（Redis PING 回显 / Mongo OP_QUERY 反射）
- `batch-recon` 命令 + tools/batch_recon.py：批量资产发现（TCP 端口存活 → Web 技术指纹 → 高价值排序 → 联动未授权检测）
- `leak-scan` 命令 + tools/leak_scanner.py：信息泄露专项（.git/.env/.svn/备份/Swagger/actuator/phpinfo 等 35 路径），SPA catch-all 与自定义 404 页误报消除
- `weakpass` 命令 + tools/weakpass.py：业务系统弱口令/默认凭据检测（表单解析+错误凭据差分 / FileBrowser API 登录器 / 通用 JSON API 登录）
- cms_fingerprint 扩展为 11 产品指纹引擎：新增 SPIP（CVE-2023-27372 RCE 映射）/ Cal.com / Odoo / Matomo / Jitsi / Plesk / FileBrowser / Nextcloud / WordPress / phpMyAdmin
### 修复
- 真实 bug：main.py cmd_idor/cmd_login `requests` 未定义 NameError（F821）
- banner 输出改走 stderr，JSON 输出保持 machine-parseable（AI/脚本可直解析）
- ruff 全量清零（多余 import / 命名 / 未用变量）、bandit High 312 → 0（指纹哈希与扫描必需项标注 nosec）
- 测试 631 → 662（新增 unauth/batch_recon/leak_scanner/weakpass/CLI 层测试）
### 背景
- 真实 SRC 授权目标实战驱动：60+ 目标批量侦察产出 3 个 Redis 未授权漏洞（212.132.104.109 / 62.116.188.86 / 167.235.142.43），并固化出上述批量实战命令

## [3.6.5] - SRC 实战化：宝塔 WAF 对抗 + CMS 版本指纹漏洞库
### 新增
- 宝塔 WAF 支持：payload_engine 新增 baota/btwaf 编码策略（双重URL/注释/空白组合），waf_bypass 识别宝塔拦截页（btwaf/您的请求已被拦截 等特征）
- cms-fingerprint 命令 + tools/cms_fingerprint.py：无损探测 CMS 版本（74cms v3/v4/v5 特征路径），匹配 data/cms_vulns.json 已知漏洞库
- data/cms_vulns.json：74cms 全系已知漏洞映射（v3.6 前台SQLi/v4.2.3 文件读取/v5.0.1 SQLi+后台RCE/模板注入/getshell 等 13+ 条）
### 背景
- 真实 SRC 目标验证：611 个 74cms 站普遍有宝塔 WAF，公开 POC 批量命中率低 -> 针对性补 WAF 对抗与版本精确指纹

## [3.6.4] - DOM XSS 框架感知 + payload 扩充
### 新增
- DOM XSS 框架 sink：Vue v-html / React dangerouslySetInnerHTML / Angular [innerHTML] / jQuery .html().append() 等 10+ 框架 sink
- DOM XSS Playwright 真实执行验证：hash 注入 payload 触发 alert 即 confirmed
- payload：ssrf.yml（云元数据/内网段/协议 20 条）、ssti_cmdi_extra.yml（$IFS 混淆等）

## [3.6.3] - 挖洞能力强化
### 新增
- DOM XSS 检测（dom-xss 命令）：抓取页面 HTML+JS 静态分析 18 种 DOM sink（innerHTML/document.write/eval/location 等）与 8 种可注入 source（location.hash/document.URL 等）配对，输出验证 payload
- payload 扩充：sqli_advanced2.yml（宽字节/二次编码/DBMS 专属变体）、xss_csp.yml（CSP 绕过/编码/DOM sink 触发 payload）——sqli_error 148 条、xss_html 63 条
### 优化
- UNION 列数探测（ORDER BY 与 NULL 两种）并行化（ThreadPool 6 并发），12 列探测提速约 6 倍

## [3.6.2] - SRC 实战教程体系
### 新增
- docs/vuln_playbooks.md：8 类漏洞实战打法（找点→验证→工具→报告）
- docs/tool_guide.md：全部命令实战参考（按 SRC 场景分类+示例）
- docs/report_writing.md：SRC 报告写作指南（复现/影响量化/红线/自检清单）
- src_hunting.md 扩充教程索引；README 增加教程入口

## [3.6.1] - IDOR/越权检测（SRC 最高频洞源）
### 新增
- tools/idor_scanner.py + idor 命令：水平越权（A 账号会话读 B 资源对比）与未授权访问检测，支持 GET 参数 / POST JSON body，A/B 双 session 对比消除误报
- payload_seeds/json_api.yml：JSON API 场景注入 payload
### 说明
- 用法：python main.py idor "https://t/api/user?id={id}" --my-id 1001 --other-id 1002 --session-file sess.json [--session-file-b b.json] [--no-auth]

## [3.6.0] - SRC 众测场景工具化
### 新增
- SRC 报告模板（tools/src_report.py）：检测结果 -> 可提交漏洞报告（描述/复现步骤/影响/修复建议，14 类漏洞模板 + Markdown 输出）
- login 命令：SRC 工作流核心 - 登录并保存 session 文件，后续 --session-file 复用登录态
- WAF 拦截识别（waf_bypass.classify_block / is_blocked）：Cloudflare/Akamai/AWS/F5/Imperva/安全狗/云盾/360 等 10 种 WAF 拦截特征
- docs/src_hunting.md：SRC 挖洞全流程手册（信息收集->定向检测->验证->报告，含工具配套用法与红线提醒）
### 说明
- 真实靶场（DVWA 等）：当前环境无 Docker，无法起真实镜像；现有验收仍为模拟靶场，后续在有 Docker 的环境补充

## [3.5.1] - 量化验收与修复
### 新增
- 10 端点漏洞靶场量化验收（lab_audit.py）：8 漏洞 + 2 无漏洞对照，检测率 100% / 误报 0
- payload_seeds 扩充：nosql.yml（$expr/$text/$jsonSchema 操作符）、oracle_extra.yml（q'[]' 引号/OPENQUERY/PG dollar-quoting）、xss 更多事件处理器
- reverse_shell / xss_browser_verify 补测试（含真实 beacon 往返）
### 修复
- **严重**: make_session/main 的 urllib3 Retry 把 HTTP 500 加入重试列表 -> 错误型 SQLi 检测完全失效（500 被重试耗尽成 RetryError 吞掉信号），且扫描慢 60 倍。500 移出 forcelist
- 补齐 DVWA 风格 MySQL 错误指纹（you have an error in your sql syntax / near 'x' at line）
- UNION 列数探测：ORDER BY 被吞时回退 UNION NULL 边界探测 + 识别 "different number of columns" 文本错误
- reverse_shell: str.format() 误解析代码块花括号（perl/node/golang/awk 模板 KeyError）-> 改 .replace()

## [3.5.0] - 高级水平升级
### 新增
- payload_seeds 分库扩充：xss.yml（事件处理器大全/编码绕过）、cmdi.yml（更多命令/OOB）、ssti.yml（多引擎 RCE 链）、lfi.yml（iconv/rot13 wrapper）
- sqli-weaponize 打通检测→数据全链：自动 表枚举→列名→行数据 dump（按 DBMS 分派）
- 二阶 SQLi 检测器（sqli-second-order 命令）：存储后触发布尔差分
- NoSQLi $where 盲注提取：JSON JS oracle 二分抽字段值

## [3.4.0] - DBMS 系统化升级
### 新增
- payload 按 DBMS 分库（mysql/mssql/postgresql/oracle/sqlite.yml）+ generate_for_dbms 接口
- 错误型检测遍历 5 大 DBMS 家族，补齐 Msg NNN/Conversion failed/ERROR: line/ORA- 指纹
- 时间盲注按 DBMS 优先选 payload
- sqli-weaponize 表枚举按 DBMS 分派（INFORMATION_SCHEMA/sys.tables/all_tables/sqlite_master）
- smuggler 新增 CL.0 检测 + 10 个混淆变体
- auto 命令 --save-report（JSON + HTML 报告落盘）
### 修复
- payload_seeds 跨文件互相覆盖的 bug（改为追加合并）
- YAML 覆盖仅首次生效的缓存 bug

## [3.3.0] - 武器化升级
### 新增
- 盲 UNION 检测（union_blind + IF() 盲注模板）
- sqli-weaponize 三条数据提取通道（union 回显/布尔盲注/盲 UNION）
- payload 引擎 versioned_comment（/*!50000*/）与 hex_str（0x 字面量）编码器
- payload_seeds YAML 外置机制

## [3.2.0] - 检测层升级
### 新增
- SQLi 黑盒上下文探测（替代参数名猜测）
- UNION 真检测：ORDER BY 列数枚举 + 唯一标记回显点定位
- 布尔盲注多采样 + 单对复验；时间盲注负对照（拒绝网络抖动误报）
- OOB 通道支持公网 dnslog（AIMY_OOB_DOMAIN / AIMY_OOB_CALLBACK_URL）
- XSS json/comment 上下文 + DOM sink 健壮性修复
