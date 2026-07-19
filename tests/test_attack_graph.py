import pytest
from tools.attack_graph import AttackGraph


class TestAttackGraph:
    def test_add_node(self):
        g = AttackGraph()
        node = g.add_node("sqli", state_type="vuln", description="SQL Injection", confidence=0.9)
        assert "sqli" in g.nodes
        assert node.confidence == 0.9

    def test_add_edge(self):
        g = AttackGraph()
        g.add_node("sqli", state_type="vuln", description="SQLi", confidence=0.9)
        g.add_node("rce", state_type="goal", description="RCE", confidence=0.0)
        edge = g.add_edge("sqli", "rce", action="exploit", transition_prob=0.8)
        assert "rce" in [e.to_id for e in g.edges.get("sqli", [])]

    def test_build_graph_from_findings(self):
        findings = [
            {"vuln_type": "sqli", "confidence": 0.9, "vulnerable": True},
            {"vuln_type": "xss", "confidence": 0.6, "vulnerable": True},
        ]
        g = AttackGraph()
        g.build_graph({"findings": findings})
        assert len(g.nodes) >= 2

    def test_propagate_probabilities(self):
        g = AttackGraph()
        g.add_node("input", state_type="start", description="Input", confidence=1.0, is_start=True)
        g.add_node("sqli", state_type="vuln", description="SQLi", confidence=0.9)
        g.add_node("rce", state_type="goal", description="RCE", confidence=0.0)
        g.add_edge("input", "sqli", action="inject", transition_prob=0.9)
        g.add_edge("sqli", "rce", action="exploit", transition_prob=0.8)
        g.propagate()
        assert g.nodes["rce"].confidence > 0

    def test_best_paths(self):
        g = AttackGraph()
        g.add_node("start", state_type="start", description="Start", confidence=1.0, is_start=True)
        g.add_node("mid", state_type="vuln", description="Mid", confidence=0.5)
        g.add_node("end", state_type="goal", description="End", confidence=0.5, is_goal=True)
        g.add_edge("start", "mid", action="step1", transition_prob=0.5)
        g.add_edge("mid", "end", action="step2", transition_prob=0.5)
        g.add_edge("start", "end", action="direct", transition_prob=0.1)
        paths = g.best_paths(min_confidence=0.01, max_depth=5)
        assert len(paths) > 0

    def test_empty_graph(self):
        g = AttackGraph()
        assert len(g.nodes) == 0

    def test_cycle_detection(self):
        g = AttackGraph()
        g.add_node("a", state_type="vuln", description="A", confidence=0.5)
        g.add_node("b", state_type="vuln", description="B", confidence=0.5)
        g.add_edge("a", "b", action="chain", transition_prob=0.5)
        g.add_edge("b", "a", action="chain", transition_prob=0.5)
        g.propagate()
        assert "a" in g.nodes
