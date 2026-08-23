# Changelog

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
