# aimy-skill 基准验收套件 (Benchmark)

用**真实靶场**验证检测能力，替代"自建 mock 靶场自说自话"。ground-truth 驱动：
每个用例标注 DVWA 官方安全级别下的期望结果（注入是否成立），跑出 TP/FP/FN/TN、
按漏洞类的召回率、precision/recall/F1 和耗时。

## 1. 起 DVWA 靶场

### 方式 A：Docker（推荐）

```bash
docker run --rm -d --name dvwa -p 8080:80 vulnerables/web-dvwa
# 首次访问 http://127.0.0.1:8080/setup.php 点击 "Create / Reset Database"
# （runner 会自动幂等执行这步，手动点一次更稳）
```

### 方式 B：Kali WSL / Linux（无 Docker）

```bash
bash bench/setup_dvwa.sh
# 默认地址 http://127.0.0.1:8081/
```

脚本会在 `/tmp/aimy-dvwa` 下启动用户态 MariaDB 和 PHP 内置服务器，不修改系统服务。
需要已安装 `php-cli` + `php-mysql`、`mariadb`、`curl`、`unzip`。
CI 也使用同一脚本运行 low/medium/high/impossible 四级别验收。

### 方式 C：XAMPP / PHPStudy（Windows 无 Docker 时）

1. 下载 DVWA 源码解压到 web 根目录（如 `htdocs/dvwa`）
2. 复制 `config/config.inc.php.dist` 为 `config.inc.php`，填 MySQL 账号
3. 访问 `http://127.0.0.1/dvwa/setup.php` 创建数据库
4. runner 用 `--base-url http://127.0.0.1/dvwa`

默认凭据：`admin / password`

## 2. 跑基准

```bash
# 完整四级别（low + medium + high + impossible）
python bench/run_bench.py --profile dvwa --base-url http://127.0.0.1:8080

# 只跑 low 级别（快速）
python bench/run_bench.py --profile dvwa --levels low

# CI 用法：出现误报或召回率不足则失败
python bench/run_bench.py --profile dvwa --fail-on-fp --min-recall 1.0
```

完整回归（无需 DVWA，先 `python lab_server.py` 起内置 25 用例 mock 靶场，
覆盖 SQLi / XSS / CMDi / SSTI / LFI / NoSQLi / SSRF / JWT / 反序列化）：

```bash
python lab_server.py &
python bench/run_bench.py --profile lab --case-timeout 30 --fail-on-fp --min-recall 1.0
kill %1
```

当前内置靶场基线：18 TP + 7 TN，0 FP / 0 FN，Precision / Recall = 100%。

当前 DVWA 基线（18 个有效用例）：12 TP + 6 TN，0 FP / 0 FN，Precision / Recall = 100%。
本机 Kali 完整四级别约 30 秒；SQLi 优先用布尔/UNION 确认，时间盲注仅在无其他证据时回退。

## 3. 读报告

产出在 `reports/bench_<profile>_<时间戳>.{json,md}`：

- **Recall（检出率）**：漏报情况，越低说明误伤能力短板
- **Precision（精确率）**：DVWA impossible 级别的 SQLi / XSS / CMDi / LFI 是负对照，
  任何 FP 都直接暴露误报问题
- **by_class**：按 SQLi / XSS / CMDi / LFI / SSTI / NoSQLi / SSRF / JWT / 反序列化分类的检出明细
- **跳过用例**：清单中 `status: skipped` 的条目——cookie 注入点、存储型 XSS、
  CSRF、弱口令爆破等超出 GET/POST 参数检测契约的能力，标注了原因和扩展方向

## 4. 扩展

在 `bench/profiles/dvwa.yml` 加用例即可（vuln_class 需对应 `run_bench.py` 的
DETECTORS 注册表）。新靶场复制一个 profile 文件改 base_url 和登录配置。
