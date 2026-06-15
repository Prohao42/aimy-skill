import ssl, socket, urllib.parse

url = "https://idcard.kesug.com/"

parsed = urllib.parse.urlparse(url)
hostname = parsed.hostname
port = parsed.port or 443

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Try multiple TLS versions
for ver_name, ver in [("TLSv1.2", ssl.PROTOCOL_TLS_CLIENT), ("TLSv1.1 (legacy)", ssl.PROTOCOL_TLSv1_1)]:
    try:
        sock = socket.create_connection((hostname, port), timeout=10)
        ssock = ctx.wrap_socket(sock, server_hostname=hostname)
        ssock.sendall(b"GET / HTTP/1.1\r\nHost: idcard.kesug.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
        data = ssock.read(4096)
        print(f"{ver_name}: got {len(data)} bytes")
        print(data[:500].decode('utf-8', errors='replace'))
        ssock.close()
        break
    except Exception as e:
        print(f"{ver_name}: {e}")
