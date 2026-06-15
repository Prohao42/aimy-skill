import ssl, socket

hostname = "idcard.kesug.com"
sock = socket.create_connection((hostname, 443), timeout=10)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ssock = ctx.wrap_socket(sock, server_hostname=hostname)

# Send request with keep-alive (like requests does)
req = (
    b"GET / HTTP/1.1\r\n"
    b"Host: idcard.kesug.com\r\n"
    b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
    b"Accept-Encoding: gzip, deflate\r\n"
    b"Accept: */*\r\n"
    b"Connection: keep-alive\r\n" 
    b"\r\n"
)
ssock.sendall(req)
data = b""
while True:
    try:
        chunk = ssock.recv(4096)
        if not chunk:
            break
        data += chunk
    except:
        break
print(f"Got {len(data)} bytes")
print(data[:500].decode('utf-8', errors='replace'))
ssock.close()
