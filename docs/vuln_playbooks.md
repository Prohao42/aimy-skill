# SRC 漏洞打法手册（找点 → 验证 → 工具 → 报告）

> 配合 aimy-skill 使用。核心原则：先人工找可疑点，再用工具快速验证，最后写报告。

## 1. SQL 注入（报错/布尔/时间/UNION）

### 找点
- 老式 PHP/Java 站点：所有带 id/uid/pid 等数字参数的接口
- 搜索框、登录（SQLi 登录绕过）、排序参数
- API 的 JSON body 字段

### 验证（工具）
    python main.py sqlcheck "https://t.com/api/user?id=1" --session-file sess.json
    python main.py sqli-weaponize "https://t.com/api/user?id=1" --session-file sess.json
    python main.py sqlcheck "https://t.com/api/user" --post --data '{"id":"1"}' --session-file sess.json

### 人工确认（防误报）
- 错误型：报错是否数据库原生错误（含表名/版本），非框架统一页
- 布尔型：true/false 响应差异是否稳定复现
- 时间型：SLEEP 延迟 vs 网络抖动（工具已做负对照，人工再确认）
- 关键：确认参数真拼进了 SQL，而非被过滤后当字符串

### 报告要点
- 接口 + 参数 + payload + 响应差异
- 影响：能读哪些数据（version/database 证明即可，严禁拖真实数据）

## 2. 越权 / IDOR（SRC 最高频）

### 找点
- 一切带数字 id 的接口：/api/user/1、/order?id=123、/file/download?id=xxx
- 关注：你的账号能否访问到别人资源的 id（订单号/文件 id 常可枚举）

### 验证（工具）
    python main.py login --auth-url https://t.com/login --auth-type form \
        --auth-user account_a --auth-pass pass_a --session-file a.json
    python main.py idor "https://t.com/api/order?id={id}" \
        --my-id 1001 --other-id 1002 --session-file a.json --session-file-b b.json
    python main.py idor "https://t.com/admin/api/users" --no-auth

### 人工确认（关键）
- 工具说越权 = A 看到的响应与 B 自己看到的一致，人工用 A 的 cookie 再请求一次
- 越权成立条件：返回的是 B 的私有数据（姓名/订单/手机号），而非通用页
- 报告必须脱敏：真实用户数据打码

### 报告要点
- 复现：A 账号 cookie + B 资源 URL + 返回的 B 数据（打码）
- 影响：能读他人哪些数据（个人信息 > 订单 > 普通数据）
- 加分：如果能改（PUT/DELETE）危害更高

## 3. 存储型 XSS（比反射 XSS 值钱 10 倍）

### 找点
- 个人资料（昵称/签名）、评论、留言板、工单、反馈
- 上传文件名回显、富文本内容

### 验证（工具）
    python main.py xsscheck "https://t.com/search?q=test" --session-file sess.json
    python main.py xss-validate "https://t.com/search?q=test" --session-file sess.json

### 人工确认（关键）
- 存储 XSS 价值 = 是否在管理后台执行（窃取管理员会话）
- payload 用 alert(document.domain) 证明执行点

### 报告要点
- 注入位置 + 触发位置 + 执行证明（截图/回连）
- 影响：管理员会话窃取 > 普通用户账号接管
- 反射 XSS 大多不收，别浪费精力

## 4. SSRF（图片代理/URL 抓取）

### 找点
- 图片/头像代理：/image?url=、/proxy?target=
- URL 预览/网页快照、PDF 生成、webhook、导入 URL

### 验证（工具）
    python main.py ssrf "https://t.com/fetch?url=http://127.0.0.1"
    python main.py ssrf-pwn "https://t.com/fetch?url=http://169.254.169.254/latest/meta-data/"

### 人工确认
- 确认目标真能访问内网（非通用错误页）
- 云元数据：AWS 169.254.169.254 / GCP metadata.google.internal / 阿里云 100.100.100.200
- 回连：用你自己的公网服务器/dnslog 确认出网

### 报告要点
- URL 参数 + 访问的内网地址 + 返回内容
- 影响：读云元数据(凭据) > 内网探测 > 仅文件读取

## 5. 命令注入 / 模板注入 / 文件包含

### 找点
- CMDi：ping/nslookup 类功能（host/ip/domain 参数传系统命令）
- SSTI：模板渲染用户输入（邮件模板预览、报表、导出）
- LFI：下载/导出/文件预览（file/path/download 参数）

### 验证（工具）
    python main.py cmdi "https://t.com/ping?host=1.1.1.1"
    python main.py ssti "https://t.com/hello?name=test"
    python main.py lfi "https://t.com/download?file=readme.txt"

### 人工确认
- CMDi：看 id/whoami 输出是否真实执行
- SSTI：7乘7 等于 49 只是第一步，确认 RCE 链（工具输出 rce_available）
- LFI：读到 /etc/passwd 后评估升级（日志投毒/上传包含 → RCE）

## 6. NoSQL 注入（Node/Go 后端）

### 找点
- 登录/查询接口参数为 JSON 对象（如 username 字段传对象）
- 支持操作符传参的 API

### 验证（工具）
    python main.py nosqli "https://t.com/login" --session-file sess.json
    # 看 where_extracted 字段（工具已做 where 盲注提取）

### 人工确认
- 登录绕过（ne 操作符）是否成功
- where 提取的数据是否真实

## 7. 逻辑漏洞（价格/订单/2FA/密码重置）

### 找点（工具难自动，靠思路）
- 支付：改价格/数量/优惠券、负数金额、并发下单
- 2FA 绕过：响应篡改、验证码重放、跳过步骤
- 密码重置：token 可预测、响应泄露 token、Host 头注入

### 验证
    python main.py bizlogic "https://t.com/checkout" --session-file sess.json

### 人工确认
- 逻辑漏洞全靠手工复现，工具只辅助记录
- 每步记录请求/响应，报告要能重现

## 8. 反序列化 / 文件上传

- 反序列化：Java/PHP 序列化数据出现在请求（cookie/base64），专用工具（ysoserial）
- 文件上传：先测类型绕过（Content-Type/双扩展名/大小写），再测解析漏洞
- 工具覆盖有限，主要靠手工

---

## 通用报告模板（所有漏洞）

    ## 漏洞标题 - 目标URL
    - 漏洞类型: xxx (CWE-xxx)
    - 危害等级: 高危/中危/低危
    - 目标: https://t.com/xxx

    ### 漏洞描述
    （一段话说明漏洞本质和影响）

    ### 复现步骤
    1. 访问: https://t.com/xxx?param=xxx
    2. 请求: （贴具体请求）
    3. 观察: （贴响应差异/截图）

    ### 影响范围
    （能读/改/执行什么，危害量化）

    ### 修复建议
    （针对性的修复）

> 提示：用工具生成初稿再人工补充：
> 见 docs/src_hunting.md 第六节 src_report 用法
