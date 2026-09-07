# AIMY-Skill Architecture Audit

## 1. 系统入口与数据流

### 1.1 入口点
```
main.py (argparse CLI)
    └── 35+ 子命令: portscan, dirfuzz, sqlcheck, xsscheck, auto, deepscan, etc.
        
        关键流程:
        - cmd_auto() -> Orchestrator -> 6阶段流水线
        - cmd_deepscan() -> Orchestrator -> 爬虫+检测+报告
        - cmd_quickscan() -> Orchestrator -> 快速高危漏洞扫描
        - cmd_autohunt() -> Orchestrator -> 自动狩猎 (爬虫+挖掘+武器化)
```

### 1.2 核心数据流 (6阶段编排)

```
用户输入 (URL/目标)
    ↓
1. 认证层 (_sess args -> auth_from_args -> TLS1.2Adapter)
    ↓
2. 快速侦察 (fingerprint_tech + scan_ports + check_git_leak + fuzz_directories)
    ↓
3. 爬虫阶段 (crawl_spa + dirfuzz -> 发现 endpoints + 参数)
    ↓
4. 探测阶段 (30+ detector 并行执行)
    │           ├─ sql_injection / sqli_blind / sqli_oob
    │           ├─ xss_detector / xss_validate
    │           ├─ ssrf_detector / ssrf_pwn / ssrf_chain
    │           ├─ ssti_detector / cmdi_detector
    │           ├─ nosqli_detector / lfi_scanner / xxe_detector
    │           ├─ jwt_detector / jwt_attacker
    │           ├─ cors_scanner / auth_bypass
    │           └─ biz_logic_scanner / proto_pollution / type_confusion
    ↓
5. 交叉验证 (VerificationOracle + cross_validator)
    │   ├─ 5+ payload 交叉验证
    │   ├─ Oracle 验证 (OOB/报错/布尔盲)
    │   └─ 误报过滤 (noise_keyword_hits, stale_seconds)
    ↓
6. 武器化层 (sqli_weaponizer + ssrf_pwn + deser_weaponizer + reverse_shell)
    ↓
7. 报告生成 (reporter.py -> JSON + HTML)
    ↓
8. Context Memory 更新 (跨模块情报共享)
```

### 1.3 关键组件分析

#### 1.3.1 _sess() 函数 (main.py:106-135)
- 创建 requests.Session, 安装 TLS1.2Adapter
- 检测 Anti-bot 挑战 (slowAES 在响应中)
- Cookie 管理 (__test cookie)
- **潜在问题**: _patched_send 的闭包捕获可能导致 session 对象意外修改

#### 1.3.2 Orchestrator (tools/orchestrator.py)
- 6阶段流水线, ThreadPool 并行
- init_storage() 持久化会话 (支持 resume)
- run() 返回 summary + detailed findings
- **关键路径**: fast_recon/high_value/turbo 模式标志控制并发和深度

#### 1.3.3 Settings (tools/settings.py)
- 环境变量驱动 (AIMY_VERIFY_SSL, AIMY_MODE, AIMY_TIMEOUT, AIMY_THREADS)
- Mode: rookie (详细) / veteran (简洁高价值)
- **配置散落**: 默认值分布在多个属性中，建议统一

#### 1.3.4 Context Memory (tools/context_memory.py)
- 单例模式 (__new__), threading.RLock 保护
- MemoryEntry: key/value/source/confidence/ttl/tags
- get_suggestions(): 按模块类型返回建议 (sqli/ssti/ssrf/cmdi/lfi/auth/exploit)
- **问题**: _auto_learn 静默更新 learnt_rules, 无法清理旧规则
- **线程安全**: RLock 但在 get_suggestions 中多次 acquire/release，存在微小竞态窗口

#### 1.3.5 Attack Graph (tools/attack_graph.py)
- GraphNode / GraphEdge / AttackPath dataclass
- 支持循环路径 (SSRF → Redis → SSRF  escalation)
- Dijkstra-based shortest path
- Confidence propagation: P(path) = Π P(edge)
- **优化机会**: 当前在 orchestrator 中有限使用，建议更深度集成

#### 1.3.6 Reasoning Engine (tools/reasoning_engine.py)
- Bayesian likelihoods (RCE:0.95, SQLi:0.90, XSS:0.70 等)
- Hypothesis 类: vuln_type, confidence, evidence, suggested_detector, priority
- update_with_evidence(): 贝叶斯后验概率更新
- analyze(): 生成 hypotheses 列表
- **优势**: 概率化的漏洞置信度，而非简单的 true/false
- **不足**: likelihoods 为静态常数，缺乏环境自适应

#### 1.3.7 Tool Registry (tools/tool_registry.py)
- 装饰器模式: detector(name, risk, tags, description)
- 懒加载 + 缓存: get(name) 返回函数引用
- run(name, *args, **kwargs): 统一执行入口
- list_all(), list_by_risk(), list_by_tag(): 检索接口
- **优势**: 统一的 Skill/Tool 注册与发现机制
- **不足**: 注册发生在模块导入时 (顶层代码), 启动延迟

### 1.4 依赖图

```
main.py
    ├── _sess() -> TLS1.2Adapter (urllib3.HTTPAdapter)
    ├── argparse -> 子命令分发
    ├── _output() -> enrich_result + filter_vulnerabilities (mode.py)
    └── --mode flag -> settings.is_rookie()/is_veteran()

orchestrator.py
    ├── _detector_kwargs() -> signature caching
    ├── ALL_DETECTORS (tool_registry 注册表)
    ├── context_memory -> get_memory() (ContextMemory singleton)
    ├── reasoning_engine -> ReasoningEngine
    ├── attack_graph -> build_attack_graph
    ├── cross_validator -> run_cross_validation
    ├── robust_verifier -> verify_finding
    ├── second_order_verifier -> SecondOrderVerifier
    ├── oob_server -> OOBServer (本地监听)
    ├── adaptive_fuzzer -> AdaptiveFuzzer
    ├── payload_engine -> payload generation
    └── tool_registry -> get_detector_config()

context_memory.py
    ├── threading.RLock (线程安全)
    ├── set()/get()/has() (MemoryEntry dataclass)
    ├── get_suggestions() (按 vuln_type 分发)
    └── _storage (可选的外部存储)

engine/ (判定引擎)
    ├── config.py -> Thresholds dataclass (集中化阈值)
    ├── diff.py -> ResponseDiffer (响应差分分析)
    ├── layering.py -> classify_family + combine_independent (证据分层)
    ├── oob.py -> OfflineOOBJudge (OOB 离线判定)
    └── reproducibility.py -> reproduction_gate (复现性验证)
```

## 2. 发现的架构问题

### 2.1 God Object / Large Functions

#### orchestrator.py: ~1990 lines
- **问题**: 单文件超大 (1990+ 行)，包含所有命令处理函数
- **影响**: 可维护性差，难以定位相关逻辑
- **证据**: 单个文件包含 cmd_portscan 到 cmd_auto 的全部 35+ 命令

#### orchestrator.py _run_detector_by_name (约 80 行)
- **问题**: 动态函数分发 (ALL_DETECTORS -> get() -> get(vtype.replace("_", "-")))
- **影响**: 难以追踪 detector 签名，参数传递不一致风险

### 2.2 Circular Dependency 风险

#### 检测到的潜在循环:
- orchestrator.py -> reasoning_engine.py -> attack_graph.py -> orchestrator.py
  (推理引擎可以生成攻克路径，攻克图可以影响推理，但当前无实际循环)
- tool_registry -> 循环导入风险 (若模块间相互 import)

### 2.3 Hidden Dependencies

#### 上下文依赖散落:
- context_memory.set("dbms", ...) 在多个 detector 中调用
- 各 detector 隐式依赖 context_memory 中的先前设置
- **风险**: 如果顺序改变 (并行执行)，检测结果可能不同
- **证据**: ssrf_detector 依赖 context_memory.get("cloud_provider")，但这可能在 SQLi 之前或之后设置

#### 阈值散落:
- engine/config.py 的 Thresholds 类是集中式的，好
- 但 orchestrator 中仍有硬编码的比率 (如 SKIP_PARAMS 集合)
- **证据**: main.py _sess 中的挑战检测正则硬编码

### 2.4 Global State

#### ContextMemory 单例:
- 全局唯一实例, 线程安全但共享状态
- **风险**: 不同目标并行扫描会互相污染上下文
- **证据**: 主程序支持 --session-file 持久化，但未在多目标场景中隔离

#### KALI_INSTANCE 全局:
- module level: KALI_INSTANCE: Optional[KaliExecutor] = None
- get_kali() 返回全局实例
- **风险**: 多线程场景下连接管理混乱

### 2.5 兼容性与遗留

#### 技术债务:
- lab_audit.py:2 - unused `json` import (已在 ruff_output 中发现)
- lab_server.py:2 - unused `time` import (已在 ruff_output 中发现)
- Import block 无序 (lab_audit.py:8)

#### 版本演进痕迹:
- CHANGELOG.md 记录 v3.5.1 量化验收，v3.5 高级水平升级，v3.4 DBMS 系统化升级
- 功能逐层叠加，未清理旧实现
- **风险**: 新旧接口不一致，向后兼容性挑战

## 3. 安全审计 (Initial)

### 3.1 Subprocess 风险

#### kali_executor.py:196 - shell=True
```python
def _run_local(command: str, timeout: int = 120) -> Dict:
    r = subprocess.run(
        command,  # nosec B602 - arbitrary user commands are the tool's core purpose
        shell=True,  # Security flag: enables shell features
        ...
    )
```
- **风险**: Command injection 如果 command 来源于不可控 input
- **当前**: 注释明确标记为预期行为，但需确保 command builder 安全
- **修复建议**: 使用列表形式而非 shell 字符串，或严格验证/转义

### 3.2 认证凭证泄露风险

#### context_memory.py
```python
memory.set("creds", {"user": "admin", "pass": "123456"}, source="auth_bypass")
```
- **风险**: 明文存储认证凭证在内存中，可通过 memory.get() 任意取回
- **影响**: 任意模块均可读取保存的凭证，可能用于后续攻击
- **修复建议**: 加密存储敏感凭证，或最小化存储时间

### 3.3 OOB 回调安全

#### settings.py
```python
oob_domain = self._env.get("AIMY_OOB_DOMAIN", "")
oob_callback_url = self._env.get("AIMY_OOB_CALLBACK_URL", "")
```
- **风险**: 默认值为空，若未配置则 OOB 通道不可用
- **影响**: 依赖外部 dnslog 服务，可能被用于数据外泄确认
- **修复建议**: 提供安全默认配置，或本地 OOB 监听作为备选

### 3.4 SSRF 元数据URL

#### context_memory.py:343-355
```python
def _cloud_metadata_url(self, cloud: str) -> str:
    # AWS: http://169.254.169.254/latest/meta-data/
    # GCP: http://metadata.google.internal/...
    # Azure: http://169.254.169.254/metadata/...
```
- **风险**: 硬编码常见云平台元数据URL，用于 SSRF 云凭据提取
- **影响**: 支持合法安全测试，也可能被滥用进行云资源扫描
- **修复建议**: 保持配置化，添加使用确认机制

### 3.5 Session 文件持久化

#### main.py cmd_login (621-649)
```python
engine.save_session(path)  # .pkl 文件
```
- **风险**: pickle 序列化潜在安全问题
- **影响**: Session 文件可被篡改劫持其他用户会话
- **修复建议**: 考虑改用 JSON + HMAC 签名，或明确警告 pickle 安全性

## 4. 性能审计

### 4.1 并发配置
- settings.py: threads property, 默认 20
- orchestrator: ThreadPoolExecutor (max_workers 参数)
- **观测**: quickscan 默认 30 线程，auto 默认 20 线程

### 4.2 重复请求潜力
- context_memory 可避免重复相同的 technology fingerprint
- 但各 detector 独立发起 HTTP 请求，存在重复探测机会
- **优化**: 在 orchestrator level 增加请求缓存

### 4.3 OOB 等待超时
- config.py: oob_callback_wait_s: float = 2.0
- **风险**: 2秒可能不足以等待公网 dnslog 回调
- **建议**: 根据环境自动调整，或提供显式超时配置

## 5. 代码质量

### 5.1 Ruff 问题 (已验证)
- 3 可自动修复的错误 (lab_audit.py/json, lab_server.py/time，import块无序)

### 5.2 MyPy 状况
- pyproject.toml: 宽松配置 (disabel 多个 error code)
- 增量启用类型检查推荐

### 5.3 测试覆盖
- 662+ tests 收集成功
- 建议: 增加 integration tests 用于 end-to-end 测试

## 6. 改进建议

### 6.1 结构优化
1. **拆分 orchestrator.py**: 按阶段拆分为子模块 (recon_engine.py, detect_engine.py, verify_engine.py, weaponize_engine.py)
2. **统一 Finding 模型**: 所有 detector 返回统一的 Finding 结构
3. **Context Memory 隔离**: 支持会话隔离，多目标并行不互污

### 6.2 接口标准化
1. **Detector 接口**: 强制统一 detect(context) -> Finding 结构
2. **Skill 接口**: 所有 hack-skill 遵循统一的 name/version/input/output/description
3. **Evidence 结构**: 标准化 evidence 字段 (request/response/headers/payload)

### 6.3 性能优化
1. **请求缓存**: 基于 URL+Method+Headers 的 HTTP 请求缓存
2. **OOB 超时自适应**: 基于网络状况自动调整等待时间
3. **并发限流**: 域名/IP 级别的并发限制，避免目标封禁

### 6.4 安全加固
1. **subprocess**: 将 kali_executor._run_local 改为列表形式
2. **credential handling**: context_memory 中敏感标记，自动清理/加密
3. **pickle 替代**: login session 文件改用 JSON + sig