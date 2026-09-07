# AIMY-Skill Refactor Plan

## Phase 0: 基线验证 (当前状态)
- ✅ ruff: 3 可修复错误 已在 ruff_output.txt 中记录
- ✅ pytest: 662 tests 收集成功
- ✅ 项目映射: PROJECT_MAP.md 已生成
- ✅ 架构审计: ARCHITECTURE_AUDIT.md 已生成

## Phase 1: 立即修复 (P0 - 1周内)

### 1.1 代码质量修复
```bash
# 运行自动修复
python -m ruff check . --fix

# 验证修复
python -m ruff check .

# 预期修复内容:
# 1. lab_audit.py: 移除 unused json import，整理 import 块
# 2. lab_server.py: 移除 unused time import
# 3. 导入顺序符合 PEP 8 / ruff 规范
```

### 1.2 为什么现在修复
- 为后续重构建立干净的代码基线
- 防止在大规模重错时引入新的 lint 问题
- 展示对代码质量的承诺

## Phase 2: 接口标准化 (P1 - 2周内)

### 2.1 统一 Detector 接口
**目标**: 所有 detector 遵循相同的输入输出契约

**当前问题**:
- 各 detector 签名不一致 (有的 url+param+ sess, 有的 url+param+timeout)
- 返回格式不统一 (有的 dict{vulnerable:true}, 有的 list, 有的自定义)

**重构方案**:
```python
# Before (示例)
# sql_injection.py
def check(url, param, sess, timeout, post=False, data=None):
    # 返回自定义格式

# After (统一接口)
# tools/_detector_base.py
from dataclasses import dataclass

@dataclass
class Finding:
    id: str
    title: str
    type: str  # "sqli" | "xss" | "ssrf" | ...
    target: str
    endpoint: str
    parameter: str
    severity: str  # "critical" | "high" | "medium" | "low"
    confidence: float
    description: str
    evidence: Dict  # {request, response, payload, ...}
    verification: Optional[Dict] = None
    references: List[str] = field(default_factory=list)

class Detector:
    name: str
    version: str
    
    async def detect(self, context: Dict) -> Finding:
        ...
```

**步骤**:
1. 定义统一 Finding 模型 (已在 ARCHITECTURE_AUDIT.md 中建议)
2. 为现有 30+ detector 创建 Adapter
3. 更新 orchestrator._run_detector_by_name 使用新接口
4. 更新 _output() 使用新 Finding 结构

### 2.2 统一 Skill 接口
**目标**: 80+ hack-skill 遵循统一契约

**当前问题**:
- Skill 之间输入输出格式不一致
- 有的返回 dict, 有的返回字符串, 有的直接 print
- 提示词 (prompt) 格式分散

**重构方案**:
```yaml
# Skill Manifest (建议目录: hack-skills/.manifest/)
skills:
  - name: sql_injection
    version: 3.7.0
    category: injection
    description: SQL injection detection
    inputs:
      url: str
      param: str
      method: str = "GET"
    outputs:
      finding: Finding  # 统一模型
    dependencies:
      - tool_registry: sql_injection
    risk: 9
    tags: [sql, injection, blind, union]
```

**步骤**:
1. 为每个 Skill 添加 __manifest__ 元数据
2. 创建 SkillLoader 读取 manifest
3. 更新 CLI 命令使用统一接口
4. 迁移现有 Skill 到新接口 (优先高频使用)

## Phase 3: 架构模块化 (P1 - 3-4周内)

### 3.1 Orchestrator 拆分
**当前**: orchestrator.py ~1990 行, 包含所有逻辑

**目标**: 拆分为职责清晰的子模块

**拆分方案**:
```
orchestrator/
├── __init__.py          # 主编排入口，序列化流程
├── recon_engine.py      # 侦察阶段 (fingerprint + port + dir fuzz)
├── detect_engine.py     # 检测阶段 (30+ detector 并行执行)
├── verify_engine.py     # 验证阶段 (Oracle + cross_validator)
├── weaponize_engine.py  # 武器化阶段 (数据提取 + 利用链)
├── report_engine.py     # 报告生成阶段 (reporter + storage)
└── engine.py            # 公共接口 + FlowControl
```

**收益**:
- 单个文件 < 400 行，更易维护
- 独立测试每个阶段
- 可选阶段跳过 (--no-chain, --skip-verify 已支持但实现分散)

### 3.2 Context Memory 升级
**当前**: 单例模式, 全局共享状态

**目标**: 会话隔离 + 持久化

**重构方案**:
```python
# Session-scoped context memory
class ScanContext:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self._memory = ContextMemory()
        self._storage = SessionStorage(session_id)
    
    def get(self, key): ...
    def set(self, key, value, ...): ...
    def snapshot(self): ...
    def restore(self, snapshot): ...

# 每个 scan 创建新 ScanContext
# 支持 --session-file 复用，但互不干扰
```

### 3.3 请求缓存层
**目标**: 减少重复 HTTP 请求

**实现**:
```python
# tools/request_cache.py
class RequestCache:
    def __init__(self, ttl: int = 300):
        self._cache: Dict[str, Dict] = {}
        self._ttl = ttl
        self._lock = threading.RLock()
    
    def get(self, key: str) -> Optional[requests.Response]:
        with self._lock:
            entry = self._cache.get(key)
            if entry and not self._is_expired(entry):
                return entry["response"]
            return None
    
    def set(self, key: str, response: requests.Response):
        with self._lock:
            self._cache[key] = {
                "response": response,
                "timestamp": time.time(),
            }
    
    def _is_expired(self, entry: Dict) -> bool:
        return time.time() - entry["timestamp"] > self._ttl
```

**应用**: orchestrator level，键 = f"{method}:{url}:{sorted(headers.items())}"

## Phase 4: 性能与稳定性 (P2 - 4-5周内)

### 4.1 subprocess 安全修复
**目标**: 消除 shell=True 命令注入风险

**当前**: kali_executor.py:196
```python
r = subprocess.run(command, shell=True, ...)  # nosec B602
```

**重构**:
```python
# 改为列表形式
r = subprocess.run(command.split(), ...)  # 或使用 shlex.split()

# 或使用参数化构建
r = subprocess.run(
    ["nmap", "-sV", target],
    capture_output=True, text=True, timeout=timeout
)
```

**证据**: Principle 12 (Agent & Tool Separation) 强调 LLM 不应直接拼接 shell 命令

### 4.2 Credential 处理加固
**目标**: context_memory 中敏感数据保护

**重构**:
1. 标记敏感键: "creds", "password", "token", "ssh_keys"
2. 自动加密存储 (或内存中仅短暂保留)
3. Clear after use: 获取凭证后立即从 memory.delete()

### 4.3 错误处理统一
**目标**: 禁止裸 Except, 统一错误分类

**当前问题** (需检查):
- `except: pass` 模式
- `except Exception: return None` 模式

**重构**:
```python
# 统一错误类
class AimyError(Exception):
    """Base aimy-skill exception"""
    
class ConfigurationError(AimyError): ...
class TargetError(AimyError): ...
class DetectorError(AimyError): ...
class NetworkError(AimyError): ...

# 错误传播原则
# - 预期错误: 捕获并记录，向上抛出 specific type
# -  unexpected error: 记录完整堆栈，友好错误信息
# - 不要吞掉异常
```

### 4.4 日志标准化
**目标**: 所有日志最少包含 session_id, task_id, status, duration

**实现**:
```python
# tools/log_utils.py
structural logger
logger = get_logger("orchestrator")

# 日志格式示例
logger.info(
    "task_start",
    extra={
        "session_id": session_id,
        "task_id": task_id,
        "target": target,
        "status": "running",
        "duration": 0.0,
    }
)
```

## Phase 5: 测试与质量 (P2 - 持续)

### 5.1 Baseline 测试
```bash
# 修改前建立基线
python -m pytest -q  # 记录 pass/fail/count

# 修改后验证
python -m pytest -q  # 不应有回归
```

### 5.2 关键测试覆盖
重点测试:
- orchestrator 流水线 (每个阶段)
- detector Adapter (新旧兼容)
- context_memory (并发、过期、持久化)
- Finding 结构 (序列化/反序列化)

### 5.3 持续集成
GitHub Actions:
```yaml
jobs:
  lint:
    runs-on: windows-latest
    steps:
      - uses: actions/setup-python@v5
      - run: pip install ruff mypy pytest
      - run: python -m ruff check .
      - run: python -m mypy .
      - run: python -m pytest --co -q
```

## Phase 6: 时间线

```
Week 1-2:   Phase 1 - 立即修复 (ruff --fix)
Week 3-4:   Phase 2 - 接口标准化 (Finding模型 + Skill Manifest)
Week 5-6:   Phase 3 - 架构模块化 (orchestrator 拆分 + Context升级)
Week 7-8:   Phase 4 - 性能稳定 (subprocess修复 + 错误处理)
Week 9+:    Phase 5-6 - 测试CI (持续验证)
```

## 兼容性保证

**不删除旧代码的原则**:
1. 每个新接口提供 Adapter 从旧到新
2. 旧命令标记为 deprecated，保留 1 个版本
3. 所有新测试先通过旧接口，再迁移新接口
4. 迁移完成后 2 个版本再删除旧代码

**风险最小化**:
- 每个阶段都有回滚方案
- Phase 1 修复完全自动，可逆
- Phase 2-4 每个子模块独立测试，可部分回滚