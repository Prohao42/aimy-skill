# aimy-skill 项目工作规范

## 项目定位
轻量级渗透测试辅助工具链（AI Agent Ready）。定位是**验证判定层**：
发现可疑点后快速确认、取证据、出报告，而不是全站盲扫。

## 目录结构
- `main.py` — CLI 入口（`aimy = "main:main"`），89 个顶层命令
- `cli/` — 参数解析与命令注册（`arg_parsers.py` / `check_commands.py`，56 个数据驱动 check 命令）
- `tools/` — 检测与利用模块（约 140 个文件；`tools/__init__.py` 为懒加载公共出口）
- `tools/orchestrator_engine/` — 编排器的侦察/测试执行/武器化子模块
- `engine/` — 判定引擎（`config` / `cvss` / `diff` / `layering` / `oob` / `reproducibility` / `contract`）
- `payload_seeds/` — 16 个 YAML payload 种子（mysql / mssql / oracle / postgresql / sqlite / xss / cmdi / ssti / lfi / ssrf / nosql ...）
- `wordlists/` — 内置弱口令字典 + john/hashcat 规则（随 wheel 打包，仅授权测试）
- `data/` — 指纹与 CMS 漏洞库（随 wheel 打包）
- `docs/` — 实战手册（`src_hunting` / `vuln_playbooks` / `tool_guide` / `report_writing`）
- `ai-mian/hack-skills/skills/` — 104 个漏洞打法技能（每个目录一个 `SKILL.md`）
- `tests/` — pytest 测试集（2946 个用例，默认离线）

## 常用命令
### 信息收集
    recon / portscan / dirfuzz / crawl / param-mine / waf
### 登录保活
    login --auth-url URL --auth-type form --auth-user U --auth-pass P --session-file sess.json
### 定向检测
    sqlcheck / sqli-weaponize / xsscheck / xss-validate / cmdi / ssti / lfi / idor / smuggler / graphql
### 编排
    python main.py auto --target URL --session-file sess.json --save-report reports/
    python main.py auto --target URL --json > report.json   # stdout 纯 JSON

命令全量参考见 `docs/tool_guide.md`。

## Claude / Agent 调用约定
- 先取工具清单，不要猜参数：
      python main.py --json manifest
  返回每个命令的 help、参数名、是否必填、类型、choices、默认值。
- 所有调用加 `--json`：stdout 只解析 JSON，stderr 是进度/日志。
- 非交互模式：不要调用 `interactive_shell` / `interactive_webshell` 等需要 stdin 的入口；
  Agent 只走一次性命令。
- 定向检测优先：`recon` / `param-mine` / `crawl` 找点，再按可疑点选
  `sqlcheck` / `xsscheck` / `ssrf` / `ssti` / `lfi` / `idor` 等；
  `auto` 只用于已授权目标的整体验证。
- 报告较大时用 `--save-report reports/` 落盘，stdout 只取 summary，避免把 details 全塞进上下文。
- 失败时读取 stdout 的 `{"ok": false, "error": ..., "code": ...}`，不要解析日志文本。
- 武器化命令（`sqli-weaponize` / `ssrf-pwn` / `reverse-shell` / `auto`）必须人工确认授权范围。
- 弱口令字典：`wordgen` 生成/合并字典（`--keywords` / `--bundled` / `--merge`），
  规则文件在 `wordlists/hashcat_common.rule` 与 `wordlists/john_custom.conf`；仅用于已授权目标。

## 开发约定
- Python >= 3.9（CI 覆盖 3.9 / 3.11 / 3.13），依赖见 `pyproject.toml` / `requirements.txt`
- 代码风格：ruff，`line-length = 100`；提交前跑 `ruff format .`
- 测试：pytest，`testpaths = ["tests"]`，默认带覆盖率统计且 `--cov-fail-under=80`
      默认离线；联网用例加 `@pytest.mark.online`，用 `--run-online` 显式开启
      `tests/conftest.py` 会让 127.0.0.1/localhost 绕过系统代理

      pytest tests/ -q
      pytest tests/test_orchestrator.py -x -q --no-cov

- 静态检查：`ruff check .` / `ruff format --check .` / `mypy tools/ engine/ cli/ main.py` / `bandit -r tools/ engine/ cli/ main.py -c pyproject.toml -lll`
- 新增检测模块后，同步在 `cli/check_commands.py` 注册命令，并补对应 `tests/`
- 新增运行时数据文件：必须放进 `payload_seeds/` 或 `data/` 包，并通过 `tools.resources`（`importlib.resources`）读取；不要用 `../` 相对路径，否则 wheel 安装后丢文件

## 平台注意事项
- 本地 Kali 工具在 Windows 上经 WSL 调用，路径统一使用正斜杠
- 本地命令执行逻辑在 `tools/kali_executor.py`：无 shell 特性的简单命令走
  `shlex.split` 列表执行；含管道/重定向的命令走 `shell=True`
- 结果统一走 `tools/output.py` 的 `output()`（stdout JSON）；进度统一走 `progress()`（stderr）
- `--json` 模式要求 stdout 只能是 JSON；新增命令不得直接 `print()` 进度
- 跨模块情报共享用 `tools/context_memory.py`（线程安全；`begin_run(target)` 会在目标切换时清理旧上下文）
- 报告输出支持 JSON / HTML / SARIF / Markdown（`tools/reporter.py`）

## 相关文档
- 架构审计：`docs/ARCHITECTURE_AUDIT.md`
- 项目地图：`docs/PROJECT_MAP.md`
- 重构计划：`docs/REFACTOR_PLAN.md`