# aimy-skill 项目地图（v3.7.6）

## 1. 定位

AI Agent 原生的渗透测试**验证判定层**：人工/Agent 找到可疑点后，用统一命令快速确认、
取证据、出报告，而不是全站盲扫。

## 2. 目录结构

```
aimy-skill/
├── main.py                    # CLI 入口（89 个顶层命令；重逻辑命令仍在此）
├── cli/
│   ├── arg_parsers.py         # argparse 构建 + 参数校验 + manifest 清单
│   └── check_commands.py      # 56 个数据驱动 check 命令（CheckSpec）
├── tools/                     # 约 141 个检测/利用/基础设施模块
│   ├── __init__.py            # 懒加载公共出口（PEP 562 __getattr__）
│   ├── orchestrator.py        # 编排器（recon → crawl → mine → auth → detect → pivot → weaponize → report）
│   ├── orchestrator_engine/   # 已拆出的侦察/测试执行/武器化/报告阶段子模块
│   ├── wordgen.py             # 弱口令字典生成/合并/内置字典读取
│   ├── resources.py           # importlib.resources 资源读取
│   ├── output.py              # JSON 输出 / stderr 进度 / 结构化错误 / CheckResult 契约
│   ├── reporter.py            # JSON + HTML + SARIF + Markdown 报告
│   └── context_memory.py      # 线程安全跨模块情报（begin_run 按目标清理）
├── engine/                    # 判定引擎：config / diff / layering / oob / reproducibility / cvss / contract
├── payload_seeds/             # 16 个 YAML 种子库（作为 Python 包随 wheel 发布）
├── wordlists/                 # 内置弱口令字典 + john/hashcat 规则（随 wheel 发布，仅授权测试）
├── data/                      # CMS/指纹 JSON 库（作为 Python 包随 wheel 发布）
├── ai-mian/hack-skills/skills/# 104 个 SKILL.md 漏洞打法技能
├── bench/                     # ground-truth 基准（DVWA / 内置 lab 靶场）
├── tests/                     # 2844 个 pytest 用例（默认离线）
└── docs/                      # 实战手册与架构文档
```

## 3. 数据流

```
CLI / AI Agent
      ↓
main.py + cli/arg_parsers.py（全局 --json / --quiet / --mode）
      ↓
Orchestrator（ThreadPool 并行，9 个 phase）
      ↓
detectors / weaponizers / engine（统一 check() → dict）
      ↓
验证层：cross_validator / oracle / false_positive_filter / second_order_verifier
      ↓
输出：stdout JSON；进度写 stderr；报告 JSON/HTML/SARIF/Markdown
      ↓
ContextMemory（目标切换自动清理） + SessionStore（resume）
```

## 4. 质量门禁

| 项目 | 当前标准 |
|---|---|
| Python | >= 3.9，CI 3.9 / 3.11 / 3.13 |
| Lint | `ruff check .` |
| Format | `ruff format --check .` |
| Types | `mypy tools/ engine/ cli/ main.py` |
| Security | `bandit -r tools/ engine/ cli/ main.py -c pyproject.toml -lll` |
| Tests | `pytest tests/ --timeout=30`，覆盖率 >= 80% |
| Package | `python -m build --wheel` + 干净环境安装 + payload 资源断言 |

## 5. 运行资源约定

- `payload_seeds/*.yml` 与 `data/*.json` 通过 `tools.resources`（`importlib.resources`）读取，
  不再使用仓库相对路径；wheel 中已验证包含 16 个 YAML + 3 个 JSON。
- PyYAML 为运行时必选依赖；OOB 回调（`AIMY_OOB_DOMAIN`）为显式可选项。
- 报告时间字段兼容 epoch 数字与 ISO 字符串。

## 6. 已知限制

- `orchestrator.py` 仍是较大的协调类（约 2200 行）；报告阶段已拆到
  `orchestrator_engine/report_phase.py`，其余 phase 拆分尚未完成。
- `tools/tool_registry.py` 仅注册 33 个可发现工具，与 88 个 CLI 命令不是一一对应；`list` 只展示 registry，Agent 应使用 `manifest` 获取完整命令/参数。
- `kali_executor._run_local` 使用 `shell=True`（执行用户命令的固有设计，已标 `nosec`）。
- 部分检测器仍返回自由 dict；`tools/output.py` 已在输出边界统一为 `CheckResult` 形状，但 detector 内部仍是自由 dict。
- `ai-mian/hack-skills` 为独立 MIT 项目（VillanCh），分发时需保留其 LICENSE/NOTICE。
