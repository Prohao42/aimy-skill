# ClaudeSec 优化演进史

> 核心主线：从"扫描器思维"升级到"验证思维"，从"文档规范"落到"可执行引擎"，再串成"可自主跑的流程"。

## 总览

| 轮次 | 主题 | 交付形态 |
|------|------|----------|
| Round 1 | 判定逻辑重构 | 验证规则文档化 + 判定引擎改造 |
| Round 2 | 判定引擎落地 | `engine/` 可执行 Python 包 |
| Round 3 | 编排层实施 | `tools/pipeline.py` 一条命令跑通 |

贯穿始终的六条原则：

1. **差分前置** — 判定先于扫描，任何检测都要有 baseline
2. **同源比较** — baseline 与 payload 必须同源（同会话/同网络路径）
3. **证据不叠加** — 共享签名库命中是相关性，不是独立证据
4. **阈值参数化** — 阈值一律参数化为相对基线比率，不写死绝对值
5. **验证思维 > 扫描思维** — AI 只填输入、读 Verdict，不做每轮现算差分
6. **业务价值 > 通用 CVSS** — 价值排序看"对这个目标最划算的攻击"，不是通用评分

---

## Round 1：判定逻辑重构（验证思维）

从"扫描器思维"（状态码、工具共识、编造修正系数）升级为"验证思维"。

### 核心改动

- **baseline-vs-payload 响应差分**：判定不再依赖 HTTP 状态码，改为 baseline 与 payload 响应的相对差分
- **证据分层**：证据按可信度分层（直接观测 / 推理 / 相关性），分层写入判定结果
- **合法 CVSS 向量推导**：CVSS 从真实观测向量推导，砍掉三类编造：
  - 状态码判据
  - 编造的 CVSS 修正系数
  - "工具共识加分"（多个扫描器命中同一漏洞，若共享签名库，只是相关性，不是独立证据）

### 落点

- `tools/verification_oracle.py` — baseline-vs-payload 差分判定
- `engine/layering.py` + `tools/false_positive_filter.py` — 证据分层与误报过滤
- `engine/cvss.py` — 合法 CVSS 向量推导

---

## Round 2：判定引擎落地（可执行引擎）

把 Round 1 的规范落成真正的 Python 引擎，AI 只填输入、读 Verdict。

### 核心改动

- **阈值参数化**：所有阈值参数化为**相对基线比率**（`engine/config.py`）
- **按漏洞类型分派复现性要求**（`engine/reproducibility.py`）：
  - 反射 XSS：一次渲染即确认
  - 时间/布尔/SSRF：多采样复现
- **离线判定路径**：补无 dnslog 的判定路径（`engine/oob.py` + `engine/diff.py`）

### 交付形态

```
engine/
├── config.py           # 阈值参数化（相对基线比率）
├── cvss.py             # 合法 CVSS 向量推导
├── diff.py             # baseline-vs-payload 差分
├── layering.py         # 证据分层
├── oob.py              # 离线判定路径（无 dnslog）
└── reproducibility.py  # 按类型分派复现性要求
```

---

## Round 3：编排层实施（可自主跑的流程）

把 recon 产物串成一条命令可跑通的管线。

### 管线阶段

```
recon 产物 → 资产图谱 → 业务价值排序 → 差分验证 → 攻击链 BFS → 报告落盘
```

### 核心改动

- **资产图谱**：`tools/pipeline.py` 的 `AssetGraph`（host/service/endpoint 节点）
- **业务价值排序**：从"CVSS 通用分"改为"对这个目标最划算的攻击"
  - 多因子：端点类型 / 技术栈风险 / CVE 命中 / 认证状态（401-403）/ git 泄露 / 已确认漏洞 / 认证绕过
  - 权值参数化（`DEFAULT_VALUE_WEIGHTS`），归一化 0–10
- **攻击链 = 图算法**：不再是 AI 灵光一现，而是资产图上 **BFS 到 crown-jewel** 的最短路径
- **crown-jewel 自动推断 + 可配置覆盖**：admin/登录/API/DB 端口/敏感端点自动推断，`override` 参数显式覆盖
- **差分验证**：预测高价值面 vs 实际确认漏洞的 hit-rate / coverage 统计
- **修复缺口**：同 host 端点不互连导致路径搜索跨不出去 —— `interconnect_same_host()` 强制同 host 端点/服务双向互连

### 接入点

- `tools/pipeline.py` — 管线入口（核心交付）
- `tools/orchestrator.py` — `phase_pipeline()` 接入 `run()` 尾段，`report["pipeline"]` 落盘
- 一条命令跑通：`aimy deepscan|quickscan|autohunt|auto <target>`

---

## 验证状态

- Round 1+2：304 tests 通过，touched files ruff clean
- Round 3：新增 `tests/test_pipeline.py`（20 用例），全量 **324 tests passed**
- ruff（line-length 100，select E/F/W/I/N）全清

---

## 关键设计决策记录（ADR 摘要）

| 决策 | 理由 | 结果 |
|------|------|------|
| 判定用相对差分而非状态码 | 状态码不可靠，差分可复现 | Round 1 |
| CVSS 由观测推导 | 编造系数/工具共识是相关性不是证据 | Round 1 |
| 阈值参数化为基线比率 | 可调、可测、不 magic number | Round 2 |
| 复现性按类型分派 | 反射 XSS 一次即真，时间/布尔需多采样 | Round 2 |
| 无 dnslog 离线判定 | 无外网/被墙环境仍可判定 | Round 2 |
| 资产图 + BFS 而非 AI 生成 | 攻击链可复现、可审计、图算法保证完备性 | Round 3 |
| 业务价值多因子替代 CVSS | 价值排序服务于具体目标攻击策略 | Round 3 |
| 同 host 互连 | 修复跨端点路径搜索缺口 | Round 3 |
