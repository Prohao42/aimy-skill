# SRC 漏洞报告: xxx人才网  数据库备份泄露

## 基本信息

- 目标: 116.xxx.23x.xxx
- 指纹: 74cms VERSION 3.3, PHP/5.6.40, Apache, MySQL 5.1.70
- 漏洞类型: 敏感信息泄露 (CWE-538 / CWE-552 未授权访问)
- 危害等级: 高危

## 漏洞描述

74cms 站点的 /data/backup/ 目录开启了目录列表且未做访问控制,
导致 67 个历史数据库备份 SQL 文件可被未授权直接下载,
泄露完整数据库内容: 管理员账号密码(哈希+盐)、求职者简历、联系方式等 PII。

## 复现步骤

1. 访问 http://116.xxx.23x.xxx/data/backup/ → 返回 200, 目录列表可见 67 个 .sql 文件
2. 直接 GET 任意备份文件, 例如:
   http://116.xxx.23x.xxx/data/backup/20130808_LXpca52030311036c1_1.sql
3. 备份文件头:
   -- 74CMS VERSION:3.3
   -- Mysql VERSION:5.1.70-cll
   -- Create time:2013-08-09
4. 全库表结构+数据可直接下载 (qs_admin / qs_members / qs_jobs_contact 等)

## 泄露证据 (已确认, 未提取全量数据)

- 表 qs_admin 结构含 admin_name / email / pwd(MD5) / pwd_hash(盐)
- 实际数据行: INSERT INTO qs_admin VALUES ('1','xiaohe','138619xxxxxx@126.com','9df071a1...','XXEuU2',...)
  (管理员账号名+邮箱+密码哈希已泄露, 密码为 MD5(密码+盐) 格式可离线破解)
- 另有 qs_simple 表泄露手机号/QQ/邮箱等求职者信息 (如 '13275xxxxxxxx','12161xxxxxx@qq.com')

## 修复建议

1. 删除服务器上的历史 SQL 备份文件, 或移出 Web 根目录
2. 为 /data/ 目录配置 deny 规则 (Apache/Nginx 禁止目录列表与直接访问)
3. 管理员密码全部重置 (泄露哈希可能被破解)
4. 检查是否有其他人已下载备份 (访问日志审计)
5. 升级 74cms 至最新版本

## 附加发现 (低危)

- /plus/, /data/, /templates/ 目录列表开放 (信息泄露)
- /data/sessions/ 会话文件 403 防护正常 (未泄露)
- /data/config.php 返回空 (被 exit 保护, 未泄露)
