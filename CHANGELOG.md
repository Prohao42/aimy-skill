# Changelog

## [3.7.6] - 2026-11-26

Agent 接入、真实靶场验收与检测可靠性版本。

### 主要变更
- **CLI/MCP 契约**: 统一 `_meta`、JSONL 与 `invalid_args` 错误协议；MCP 只暴露 104 个可执行工具并复用 CLI 校验。
- **并发隔离**: 输出上下文改为 `ContextVar`，MCP 命令串行执行，避免 stdout、request_id、tool 串线。
- **能力自检**: 新增 `doctor`，检查依赖、MCP、Playwright、Kali、OOB 和目录权限。
- **真实靶场**: 新增可移植 DVWA 启动脚本和四级别 CI 验收；内置靶场扩展到 25 用例、9 类漏洞。
- **检测修复**: 修复 LFI/CMDi/JWT/SAML/SMB/双会话/竞态的误报与成功判定缺陷；CMDi 增加 POST 支持。
- **性能**: SQLi 单点约 25s→0.7s，CMDi 约 9-11s→2.1s，完整 DVWA 约 90s→30s。
- **版本指纹**: CVE 匹配改为显式版本区间，移除“主版本号当年份”的错误匹配。
- **跨平台**: 修复 Windows `ping`/`ipconfig`、报告文件名、GBK 测试解码和 PDML 解析回退。
- **CI**: 增加 Windows 全量测试、25 用例内置靶场和 DVWA 四级别任务。

### 验证
- 全量测试 **2946 passed**，覆盖率 **85.08%**。
- 内置靶场 **18 TP / 7 TN / 0 FP / 0 FN**。
- DVWA **12 TP / 6 TN / 0 FP / 0 FN**，Precision/Recall 均 100%。
- Ruff、格式检查、Mypy 全绿。

## [Unreleased] - 质量收尾 (mypy 清零 · 覆盖率 49%→72% · 缺陷修复)

全量 `1955 passed` (本机 Python 3.14), `ruff`/`mypy`/`bandit` 全绿。

### 静态与质量
- **mypy: 27 errors → 0** (163 文件)。修复 `Orchestrator.sess` 非空保证、`OPSECSession.request` 签名兼容 (补 `*args` 转发)、`len(object)` / `str|None` 推断等。
- **覆盖率: 49% → 72%** (23529 行, 未覆盖 12066 → 6682)。新增 ~980 条离线 mock 测试: orchestrator 35→99%, second_order_verifier 39→100%, robust_verifier 11→100%, ssrf_pwn/ssrf_chain 12/18→100%, workflow_tracer 32→100%, crawler/binary_search/attack_tree/constraint_graph/spa_crawler →100%, 9 个 0% 模块 (kali_toolset/mitm_proxy/domain_hunt 等) →94-100%。
- **bandit High: 2 → 0** (`dir_fuzzer` MD5 指纹按仓库惯例标注 `# nosec B324`)。

### 缺陷修复 (新增测试覆盖中发现, 全部带复现)
- **`orchestrator`**: 干净目标 (无 finding/无 auth bypass) `run()` 抛 `UnboundLocalError: exploits`; attack_plan 的 `sql_injection` 映射到不存在的检测器名 (→ `sqlcheck`); fast 模式 critical 判断用错名字 (`vtype` 是注册名) 导致 SQLi 不触发低价值检测器禁用; 删除 `found_critical` 死代码。
- **`second_order_verifier`**: XSS html_context 成功正则 `<aimy[0-9]+>` 与探测载荷 `<aimy_xss_%d>` 永不匹配 (死方法) → 对齐; LFI `known_file` "任意非空 body 即成功" → 负对照 (不存在文件) + 反射守卫; NoSQLi `is_post=True` 无 data 时载荷被丢弃 → `url_nosql` 两分支均赋值。
- **`robust_verifier._lfi_encode_path`**: 恒返回 `encodings[0]`, `%2f`/`..;/`/`php://filter` 等编码绕过全是死代码 → 返回全部变体并逐变体探测。
- **`context_memory._php_wrappers`**: 版本比较 `major>=7 and minor>=4` 把 PHP 8.0 当 <7.4 → 改 `(major, minor)` 元组比较。
- **`sqli_blind.run(queries=...)`**: 调用方查询被静默忽略 → 注入提取项 (`custom_queries`)。
- **`ssrf_chain._chain_docker`**: `DOCKER_PAYLOADS` 键值反解包 (`for path, desc`) 拼出畸形 URL (`:2375containers`), Docker 链永不成功 → `(name, path)` 正确解包。
- **`attack_tree`**: 模板第 4 元素为子节点列表时被误存到 `chain_name` 且孙节点永不展开 (递归分支死代码); 5 元组路径 ID 双前缀 → 递归展开 + 单前缀。
- **`constraint_graph`**: `limit_like` 死代码 (limit/max/min 参数无约束) → `limit_manipulation` 约束 + 变异建议; 删除空循环。
- **`binary_analyzer`**: 4 个崩溃点 —— `_calc_entropy` 对 float 调 `bit_length()` (任何二进制分析恒空)、packer 名 str/bytes 比较 TypeError、ELF `e_phoff` 切片长度错误 (任何 ELF 解析失败)、截断可选头 `magic` 未赋值 → Shannon 熵 / bytes 比较 / 按 32/64 位规范偏移 / 长度守卫。
- **`domain_hunt`**: import 不存在的 `run_kali_cmd` (域审计主流程 ImportError) → `get_kali()`; kerberoast 缺 `servicePrincipalName` 属性时整段枚举中断 → try/except 跳过。
- **`cloud_pwn`**: AWS 正则不消费分隔符 (`AccessKeyId: AKIA` → `":"`)、GCP/Azure 懒量词只取 1 字符、Azure 凭据 (JWT/tenant) 误路由到 GCP 分支 → 正则重写 + 按 project_id/tenant_id/`eyJ` 前缀路由。
- **`kali_toolset`**: `sqlmap_extract(queries=...)` 参数未接线 (静默无操作) → 真正拼入命令; dump 解析正则 `\[(\d+)\]` 与 sqlmap 输出 `[N entries]` 不匹配 → 修正; nmap `443/open|filtered/tcp` 永不识别 → 逐 token 正则补齐组合状态。
- **`mitm_proxy`**: `CalledProcessError.stderr` 为 None 时 `.decode()` 崩溃 → 类型守卫。

### 挖洞能力强化 II: 检测/利用缺陷批量修复 (覆盖率 72% → 85%, 60+ 项)
最终验证: **2833 tests passed** (CI 等价 `--timeout=30`), 覆盖率 85% (23691 行), `ruff`/`mypy` (163 文件 0 错误) 全绿, bandit 无 High; 加固靶场 19 端点 15/15 检出 + 4/4 无误报, bench Precision/Recall/F1 = 100%/100%/1.000。
在 5 个并行覆盖+缺陷挖掘任务中对剩余低覆盖模块补离线测试 (~1050 条), 并修复其中暴露的检测/利用缺陷 (全部有最小复现, 测试同步更新为修复后行为):
- **核心检测**: `active_prober` body 探针读错键 (`probe["regex"]` vs `["body"]`) 导致 WordPress/Drupal/Spring 等全部 body 指纹失效 → 修正; `_probe_banner` 从空 stub 实现为真实 socket banner 抓取 (SSH/Redis/MySQL, redis 先发 `INFO`); 404/5xx 页不再参与版本指纹 (0.85 置信误报); 探针异常不再静默吞。
- **SSRF**: 云元数据证据移除泛化 `<Name>/<Contents>/<Key>` (普通 XML 误报); `172.*` 按 RFC1918 收窄到 172.16-31 (172.217 公网不再算内网); `internal_reachable` 增加不可达端口负对照; OOB 重试不再降级丢失 payload/confirmed。
- **语义/响应分析**: 空文本相似度恒 1.0 修复; ≤5 字符载荷反射漏检修复; 深层 `<script>` 上下文误判修复; `structure_hash` 改用 md5 (内建 hash 跨进程随机化); python 错误正则收紧 (散文误报); Content-Type/header 键大小写不敏感; `datetime` 分支不可达修复; 500 页 SQL 正文归类修复; `message:` 误判错误页修复; `_infer_resource` 字符类笔误修复。
- **自动渗透/fuzz**: `auto_pwn` learn 丢弃 `success=True` 导致循环误停修复; CVE 探测 success 收紧 (503/401/302 不算成功) 且未实现向量显式标注不再误导性通用探测; fuzz 模板缺占位符不再生成垃圾载荷 ("1 1 1"); 未知类型不再回退全语法池; 超时载荷不再丢弃 (time-based 信号); baseline 失败不再全量误报 interesting; 参数挖掘仅记录真实差异 (恒 200 站点不再全量误报 61 个参数); POST 挖掘用 POST baseline; adaptive avoid 命中直接排除。
- **利用链/横向/JWT/类型混淆**: `chain_engine` 凭据去重对 dict 崩溃 (恰在窃到凭据时) 修复; 内网探测/gopher RCE 不再把 404 计为成功; `db_lateral` sqsh/sqlcmd 改用 shlex 保留引号, cmdshell 增加 sqsh 回退 + 单引号转义; `jwt_attacker` 畸形 `alg` 头不再中断扫描; `type_confusion` 无 `param=` 的 URL 不再丢弃 payload, prototype_pollution 需服务端证据 (不再仅凭载荷判成功)。
- **认证/会话/CSRF/竞态**: `session_matrix` 登录判定收紧到 200 (302/500 不算成功), basic 认证凭据显式持久化, `authz_gap` 要求真实差异 (相同 body 不再误报); `csrf_scanner` meta token 正则修复 (`<meta name="csrf-token">` 可匹配), 无 action 表单可解析, 表单级 token 精确匹配, 任意 POST 表单不再直接判漏洞, bypass 需正文无失败标记; `race_profiler` `_analyze_window` 参数错位修复 (基线体比对恢复), `cross_validator` 二阶确认 URL 不再子串改写相似参数。
- **HTTP 客户端/WAF**: `http_client` 注入的 Session 现在真正用于请求且 `params/json/cookies` 不再静默丢弃 (二阶验证假阴性根因之一), 挑战标记窗口与全文正则对齐; `waf_bypass.is_blocked` 的 threshold 参数接线生效。
- 说明: 各挖掘任务另报告了约 40 项设计级问题 (如 deviation_oracle 的约束伪造、jwt alg-none 仅检测不发包、race_profiler 幂等端点判定等), 属重构级改动, 未在本轮处理。

### 挖洞能力强化: 加固靶场 (10 → 19 端点) + 检测修复
- **靶场加固**: 新增 `sqli_post`/`xss_post` (POST 契约)、`xss_attr`/`xss_js` (属性/脚本上下文)、`ssti_alt` (仅 `${7*7}` 的备用引擎)、`lfi_hardened` (仅 `....//`/`%2f` 编码可绕过)、`nosqli_get` (GET 操作符注入) 与 `clean_attr`/`clean_ssti` 两个误报护栏; `bench/profiles/lab.yml` 与 `lab_audit.py` 同步扩到 19 例。
- **量化结果**: 加固首轮 13/15 检出 (暴露 2 个真实假阴性) → 修复后 **15/15 TP + 4/4 TN, 0 FP/FN, Precision/Recall 100%, F1=1.000** (bench harness 同分)。
- **`xss_detector` 假阴性+误报根因**: `_payload_reflected_unescaped` 对不含尖括号的载荷 (属性/事件处理器类) 因 `escaped == payload` 恒判"已转义", attr 上下文确认路径整体失效 (xss_attr 漏报); 修复后新增 `_attr_breakout_ok` 按引号风格校验突破字符 (双引号属性里的裸单引号不算 XSS), 同时消除 clean_attr 误报。
- **`nosqli_detector` GET 操作符注入**: boolean 种子全是 `$where` 风格, 不含 `$ne/$gt`, 差分确认分支永不触发 → 新增 `_confirm_operator_blind` (基线锚定 + `$ne/$gt` 双族 + 重复稳定性, 抗通用特殊字符/错误页/WAF 403 误报) 与廉价探针接入; 检出类型 `operator`。
- 新增回归单测: `_payload_reflected_unescaped`/`_attr_breakout_ok` 矩阵与操作符差分确认 (含拒绝路径)。

### 已知限制 (未修复, 见评审)
- `deser_weaponizer` 的 Java/.NET/Ruby 生成器为骨架式载荷: 接受 `cmd` 但不嵌入 (产物与命令无关), 需针对真实运行时实现完整序列化链, 本轮不动。
- `robust_verifier` 时间盲注 `confirmed >= 2` (置信度 0.8) 分支在延迟证据路径上极难触发, 属设计气味, 保持原逻辑。
- `weaponize_engine.py:209-210` 不可达 `except` (被 `_run_aws` 吞异常), 保留。

## [Unreleased] - 检测能力专项修复 (编排器 0 检出 → 8/8, 0 误报)
### 能力修复: 编排器端到端检测 (10 端点靶场量化)
基线: `auto http://target/page?id=1` 产出 **0 测试点、0 检出**; 逐个检测器直调 8/8。
最终: **编排器 8/8 检出 (类型全对)、0 误报** (开验证层)。靶场审计 8/8 TP / 2/2 TN / 0 FP / 0 FN。

- **`sql_injection._detect_error_sqli` 不设置信度** (根因):
  返回 dict 无 `confidence_score`, 且 `check()` 在首个命中处 `break`, 导致
  `vulnerable=True, confidence_score=0.0`, 被 FPF 以 `low_confidence` 丢弃.
  → 补充 confidence (2+ 错误模式=0.85 high, 单条+DBMS 泄漏=0.65 medium),
  并让 `check()` 保留**最高置信度**结果而非盲信首个命中.
- **`sql_injection._detect_union_sqli` 同样不设置信度** → 补 0.85/0.6
- **`sql_injection._detect_union_sqli` 反射误判**:
  端点原样回显 payload 时, UNION marker 全部"出现" → 误报 UNION 注入.
  → 加反射守卫: payload 被回显则不计反射 (真 UNION 结果含求值后 marker 但不含 payload 原文).
- **`ssti_detector` 反射误判** (两处):
  - 主循环 `indicator in r.text`: `{{config}}` 回显时 indicator "config" 作为子串出现 → 误报.
    → 加 `_is_reflected()` 守卫 (payload 被回显则不计).
  - 布尔盲注 `r_true.text != r_false.text`: 回显时 payload 文本不同即判命中.
    → 改用长度差判据 (真求值 20 vs 1 字符=19 差; 纯回显仅差 1).
- **`lfi_scanner` 不填 `evidence`**: 有 `findings` 但无 `evidence`, 被 FPF
  `insufficient_evidence` 丢弃 → 从 findings 派生 evidence 字符串.
- **`auth_bypass` 无 catch-all 检测**: `/admin` 等路径全 200 时产出 63 条假绕过
  → 加 `_catchall_signature` 随机路径探测 + 长度容差过滤 (与 dir_fuzzer 同套).
- **`SKIP_PARAMS` 误含 `file`**: `?file=` 是最常见 LFI/文件读取参数, 被跳过
  → 移除 (orchestrator 此前永远测不到 `?file=` 端点).
- **`sqli_blind._measure_baseline` 可返回 0.0**: mock/缓存响应低于时钟精度时
  返回 0, 破坏下游 ratio 计算 → 下限 0.001.

### 能力修复: 编排器测试面 (真实检测能力, 用 10 端点靶场量化验证)
- **`dir_fuzzer` 增加 catch-all 检测** (`tools/recon/dir_fuzzer.py`):
  之前 `status_code != 404` 即视为"发现"; SPA / 自定义错误页 / WAF 对任意
  路径返回同一 200 页面时, 200 个假路径全部入选, 把真正端点挤出时间预算.
  现在先用两个随机路径探测 catch-all 签名 (md5), 命中则按 body 去重过滤.
  靶场实测: `catchall_skipped=218`, `interesting=0` (之前 200 个假路径).
  新增返回字段 `catchall_detected` / `catchall_skipped`.
- **`_build_test_points` 纳入种子 URL 自身参数** (`tools/orchestrator.py`):
  `auto http://target/page?id=1` 是最自然用法, 但旧实现只从 crawl/dirfuzz/
  js_api/attack_plan 取点, 完全忽略 URL 里已写明的 `id` 参数 → **0 测试点**.
  新增 `_seed_points_from_target()`, 靶场实测: 测试点 0 → 1, `auto` 命令
  终于能在带参 URL 上工作.
- **修复 `base_target` 路径拼接** (`tools/orchestrator.py`):
  `self.target` 含 query 时, `self.target + "/path"` 会产生畸形 URL
  (`/page?id=1/x`), 靶场实测导致 70 个垃圾误报. 新增 query-stripped 的
  `self.base_target` 专供路径拼接, 误报 70 → 1.
- 新增测试: `tests/test_dir_fuzzer.py` (7), `test_orchestrator.py` +6

### 已解决的前轮缺口
- **验证层"过度过滤"实为检测器置信度为 0**: oracle/FPF 正确地丢弃了
  `confidence_score=0.0` 的结果; 真因在 `_detect_error_sqli` / `_detect_union_sqli`
  未设置信度. 补齐后真 SQLi 正常通过验证层.
- **`nosqli` 在 SQLi 端点误报**: 改为 TRUE/FALSE 差分 oracle (见下).

### 新增
- **AI-Agent 契约模块** `engine/contract.py`: `CheckResult` dataclass + `check_return_shape()` + `is_vulnerable()`, 为所有 `check()` 返回值提供软校验 (REQUIRED: `vulnerable: bool`)
- **orchestrator test runner** `tools/orchestrator_engine/test_runner.py`: 从 `Orchestrator` 类抽出无状态 helper (`run_detector` / `cross_verify`), 允许脱离实例单测
- **orchestrator chains** `tools/orchestrator_engine/chains.py`: 利用链调度表单一真相源 (by_vtype / by_name 两个视图派生自同一张表, 消灭 backtrack / pivot 路径的分叉)
- **orchestrator weaponizer** `tools/orchestrator_engine/weaponizer.py`: 按 vtype 分派的武器化 (`weaponize_sqli/ssrf/lfi/xss/jwt/one`), 替代 phase_weaponize 内嵌 105 行 `_weaponize_one`
- **JWT common** `tools/jwt_common.py`: `b64url_encode/decode` + `parse_jwt` 单一真相源, jwt_exploiter/jwt_attacker/jwt_detector 统一委托
- **测试**: `tests/test_contract.py` (24), `tests/test_test_runner.py` (8), `tests/test_weaponizer.py` (7), `tests/test_jwt_common.py` (15), `tests/test_orchestrator.py` (+5 phase_detect helper 单测)

### 修复 (bug, 不只是 lint)
- **check() 契约坏味道** (4 个检测器):
  - `tools/leak_scanner.py`: 缺 `vulnerable` 顶层字段
  - `tools/waf_bypass.py`: 缺 `vulnerable` 顶层字段 (AI agent 会默认判 False)

### 修复 (bug, 不只是 lint)
- **check() 契约坏味道** (4 个检测器):
  - `tools/leak_scanner.py`: 缺 `vulnerable` 顶层字段
  - `tools/waf_bypass.py`: 缺 `vulnerable` 顶层字段 (AI agent 会默认判 False)
  - `tools/weakpass.py`: 缺 `vulnerable` 顶层字段
  - `tools/unauth_scan.py`: `vulnerable` 字段是 int 计数而非 bool, 严重误导 agent 分支; 改为 bool, 计数改名为 `_vulnerable_count`
- **同名类冲突**: `tools/vuln_context.ContextMemory` 与 `tools.context_memory.ContextMemory` 重名, 重命名为 `VulnContextStore`

### 清理
- **死代码删除** (4 个文件, 287 行):
  - `tools/_context.py` (90 行, 0 外部引用)
  - `tools/orchestrator_engine/detect/detect_engine.py` (160 行, 已被 helpers 替代)
  - `tools/orchestrator_engine/__init__.py` (9 行, 空)
  - `payload_seeds/oracle_extra.yml` (28 行, 缺 `seeds:` 顶层键, 运行时静默丢弃)
- **orchestrator 上帝模块瘦身**: 1934 → 1696 行 (-12%):
  - 提取 `_run_detector` / `_cross_verify` 到 `test_runner.py`
  - `phase_detect` (224 行) → 5 个私有方法 (`_fingerprint_waf_cached`, `_phase_detect_scan`, `_phase_detect_semantic`, `_phase_detect_second_order`, `_phase_detect_type_confusion`, `_phase_detect_bayes`), 主方法压到 ~40 行编排骨架
  - `phase_weaponize` 内部 `_weaponize_one` (105 行) 抽出为模块函数 `weaponizer.py`
  - chain 表两处重复合并为单一真相源 `chains.py`
  - `phase_pivot` (155 行) → 1 个 40 行编排骨架 + 8 个 pivot handler 方法 + dispatch table
  - `phase_report` (100 行) → 1 个编排 + `_report_group` / `_report_summary` / `_report_recon` / `_report_persist` 四个静态/实例方法

### 死代码 / 重复清理
- **JWT base64 重复**: `jwt_exploiter.b64_encode/decode` 与 `jwt_attacker.b64url_encode/decode` 实现等价但命名误导; 抽到 `tools/jwt_common.py`, 三模块统一委托
- **`jwt_detector._b64_pad`**: 删除, 改用 `b64url_decode`

### 文档
- `tools/biz_logic_scanner.py` / `tools/biz_logic_v2.py`: 顶部 docstring 明确两者关系 (classic 单体 vs v2 模块化聚合器), 消除"v1/v2 哪个是当前用"的歧义

### 检测器级修复
- **`nosqli_detector` 布尔误报**: 旧实现只看"响应长度与基线差 >30"即判命中,
  SQL 错误页会让每个特殊字符 payload 产生恒定长度差 → `/sqli_error` 被误报为 nosqli.
  → 改为 **TRUE/FALSE 差分 oracle**: TRUE 与 FALSE 条件必须产生**彼此不同且稳定**
  的响应; 恒定的"与基线不同"被拒绝. 新增 `_confirm_boolean_blind()`.
  真 NoSQL (JSON `$where` 分支) 仍正常检出.

### 测试基线 (从假 100% 修正为真实数字)
- 修复前: 845/875 通过 (CHANGELOG 误报 100%)
- 第二轮: 907/907; 第三轮: 933/933; 第四轮: 939/939; 第五轮: 952/952
- **当前: 972/972 通过** (真正零失败)
- ruff: 27 → **0** (持续守住)
- mypy: 29 → 23 (剩余多为动态类型推断噪音, 非行为问题)
- 靶场 `lab_audit.py`: 8/8 TP, 2/2 TN, 0 FP, 0 FN (100% 准确率)
- 编排器端到端 (开验证层): **8/8 检出, 0 误报**

## [3.7.5] - 未提交重构修复 + 全量静态清零

## [3.7.5] - 未提交重构修复 + 全量静态清零
### 修复（阻塞级）
- **CLI 启动即崩**：file-upload / saml-sso 子命令重复注册 `--param`（argparse 冲突），全部命令不可用 → 删除重复注册
- **auto 流水线崩溃**：orchestrator 拆分时误删 `SKIP_PARAMS` / `SIGNATURE_PLACEHOLDER` 常量（8 处引用 NameError）→ 恢复定义
- **recon 引擎契约断裂**：recon_engine 简化版返回结构与 orchestrator 期望不符（interesting/resolved/open_count 等），且 `enum_subdomains(threads=/wordlist=)`、`fuzz_directories(follow_redirects=)` 签名不匹配（TypeError / 子域名枚举静默失效）→ recon_engine 重写为 tools/recon/ 真实现的薄委托
- **auto-pwn 检测器注册失败**（33 名 vs 32 实现）：auto_pwn 模块级 import orchestrator 形成循环导入 → Orchestrator 延迟到方法内导入
- **统一 Finding 模型四处崩溃**：`VulnType.INFO` 枚举成员被删（6 处引用）、`Evidence` 缺 `to_dict()`、`OldFormatFinding.adapt` 的 type_map 仅 12/32 且兜底值非法、output.py 死循环导致 Finding 无法 JSON 序列化 → 全部修复，type_map 扩充别名、evidence 可选化
### 优化
- ruff 25 错 → 0（F821×9 / F401×13 / F841 / I001×2）；mypy 62 → 26（剩余为武器化/横向模块的类型噪音，非运行时错误）
- tools/session.py：http:// 目标也挂 TLS1.2+重试适配器（与 https 行为一致）
- tools/challenge.py：远程 aes.js 执行黑名单加固（constructor 链/动态导入/网络外联/编码执行等逃逸姿势）
- 删除死代码 tools/sqli_adapter.py（全仓零引用）
### 仓库卫生
- .gitignore 白名单 data 功能数据（cms_vulns / cms_map / fingerprint / backup_leaks*），此前 clone 后 CMS 指纹漏洞库静默缺失
- data/src_targets.txt 停止跟踪并加入 ignore（敏感目标清单，历史中仍存在，需 git filter-repo 清理）
- 补根目录 LICENSE（MIT）；README 徽章校准（147 modules / 93 commands / 663 tests）+ hack-skills (yaklang/VillanCh) 致谢；版本号三处对齐 3.7.5

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
