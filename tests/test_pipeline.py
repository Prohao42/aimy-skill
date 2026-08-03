from tools.pipeline import (
    bfs_to_crown_jewel,
    build_asset_graph,
    differential_verify,
    endpoint_id,
    host_id,
    infer_crown_jewels,
    port_id,
    run_pipeline,
    score_assets,
)


def _sample_state():
    return {
        "phases": {
            "recon": {
                "technologies": {
                    "technologies": [
                        {"id": "spring", "name": "Spring Boot", "version": "5.3"},
                        {"id": "mysql", "name": "MySQL"},
                    ]
                },
                "open_ports": {
                    "open_ports": [
                        {"port": 80, "service": "http", "state": "open"},
                        {"port": 3306, "service": "mysql", "state": "open"},
                        {"port": 6379, "service": "redis", "state": "open"},
                    ]
                },
                "directories": {
                    "interesting": [
                        {"path": "/admin", "status": 200, "size": 100},
                        {"path": "/login", "status": 200, "size": 80},
                        {"path": "/assets", "status": 200, "size": 50},
                    ]
                },
                "git_leak": {"git_exposed": False, "sensitive_finds": []},
            },
            "crawl": {
                "endpoints": {
                    "/admin/dashboard.php": {
                        "url": "http://target.test/admin/dashboard.php",
                        "methods": ["GET"],
                        "params": ["id"],
                    },
                    "/api/user": {
                        "url": "http://target.test/api/user",
                        "methods": ["GET"],
                        "params": ["uid"],
                    },
                }
            },
            "param_mine": {"/login.php": {"all_params": ["user", "pass"]}},
            "detect": {
                "findings": {
                    "sqli|http://target.test/admin/dashboard.php|id": {
                        "type": "sql_injection",
                        "url": "http://target.test/admin/dashboard.php",
                        "param": "id",
                        "vulnerable": True,
                        "confidence_score": 0.9,
                    }
                }
            },
            "auth_bypass": {
                "path_bypasses": [{"url": "http://target.test/api/user"}],
                "cookie_bypasses": [],
                "header_bypasses": [],
                "method_bypasses": [],
            },
        }
    }


class TestCrownJewels:
    def test_infer_from_admin_path(self):
        state = _sample_state()
        jewels = infer_crown_jewels(state, "http://target.test")
        assert endpoint_id("http://target.test/admin") in jewels

    def test_infer_from_db_port(self):
        state = _sample_state()
        jewels = infer_crown_jewels(state, "http://target.test")
        assert port_id("target.test", 3306) in jewels
        assert port_id("target.test", 6379) in jewels

    def test_infer_from_high_value_tech(self):
        state = _sample_state()
        jewels = infer_crown_jewels(state, "http://target.test")
        assert any(j.startswith("tech:spring") for j in jewels)

    def test_override_wins(self):
        state = _sample_state()
        jewels = infer_crown_jewels(state, "http://target.test", override=["custom"])
        assert jewels == ["custom"]


class TestAssetGraph:
    def test_build_has_host_service_endpoint(self):
        g = build_asset_graph(_sample_state(), "http://target.test")
        assert host_id("target.test") in g.nodes
        assert port_id("target.test", 3306) in g.nodes
        assert endpoint_id("http://target.test/admin") in g.nodes

    def test_same_host_endpoints_interconnect(self):
        g = build_asset_graph(_sample_state(), "http://target.test")
        a = endpoint_id("http://target.test/admin")
        b = endpoint_id("http://target.test/api/user")
        assert b in g.adj.get(a, set())

    def test_same_host_service_linked_to_endpoint(self):
        g = build_asset_graph(_sample_state(), "http://target.test")
        svc = port_id("target.test", 6379)
        ep = endpoint_id("http://target.test/admin")
        assert svc in g.adj.get(ep, set())

    def test_finding_adds_evidence(self):
        g = build_asset_graph(_sample_state(), "http://target.test")
        nid = endpoint_id("http://target.test/admin/dashboard.php")
        assert any(e.startswith("finding:sql_injection") for e in g.nodes[nid].evidence)

    def test_bfs_shortest_path_to_crown(self):
        g = build_asset_graph(_sample_state(), "http://target.test")
        paths = g.bfs(
            [host_id("target.test")],
            [endpoint_id("http://target.test/admin")],
        )
        assert paths
        assert paths[0][-1] == endpoint_id("http://target.test/admin")
        assert paths[0][0] == host_id("target.test")

    def test_empty_state(self):
        g = build_asset_graph({}, "")
        assert len(g.nodes) == 1
        assert g.summary()["total_edges"] == 0


class TestScoring:
    def test_admin_outranks_assets(self):
        state = _sample_state()
        g = build_asset_graph(state, "http://target.test")
        scores = score_assets(g, state)
        admin = endpoint_id("http://target.test/admin")
        assets = endpoint_id("http://target.test/assets")
        assert scores[admin] > scores[assets]

    def test_vulnerable_endpoint_scores_high(self):
        state = _sample_state()
        g = build_asset_graph(state, "http://target.test")
        scores = score_assets(g, state)
        vuln = endpoint_id("http://target.test/admin/dashboard.php")
        assert scores[vuln] >= 6.0

    def test_critical_service_scores_high(self):
        state = _sample_state()
        g = build_asset_graph(state, "http://target.test")
        scores = score_assets(g, state)
        redis = port_id("target.test", 6379)
        assert scores[redis] > scores[port_id("target.test", 80)]

    def test_scores_capped_at_ten(self):
        state = _sample_state()
        g = build_asset_graph(state, "http://target.test")
        scores = score_assets(g, state)
        assert all(v <= 10.0 for v in scores.values())


class TestBfsToCrownJewel:
    def test_finds_chain_from_proven_surface(self):
        state = _sample_state()
        g = build_asset_graph(state, "http://target.test")
        scores = score_assets(g, state)
        jewels = infer_crown_jewels(state, "http://target.test")
        chains = bfs_to_crown_jewel(g, scores, jewels)
        assert chains
        assert chains[0]["hops"] >= 1
        assert chains[0]["target"] in jewels

    def test_no_jewels_no_chains(self):
        state = _sample_state()
        g = build_asset_graph(state, "http://target.test")
        scores = score_assets(g, state)
        assert bfs_to_crown_jewel(g, scores, []) == []


class TestDifferentialVerify:
    def test_confirmed_high_value_detected(self):
        state = _sample_state()
        g = build_asset_graph(state, "http://target.test")
        scores = score_assets(g, state)
        jewels = infer_crown_jewels(state, "http://target.test")
        diff = differential_verify(g, scores, jewels, state)
        assert diff["confirmed_endpoints"] >= 1
        assert diff["expected_high_value"] >= 1


class TestRunPipeline:
    def test_report_section(self):
        state = _sample_state()
        report = run_pipeline(state, "http://target.test")
        assert report["target"] == "http://target.test"
        assert "asset_graph" in report
        assert report["asset_graph"]["total_nodes"] > 0
        assert isinstance(report["crown_jewels"], list)
        assert isinstance(report["top_assets"], list)
        assert isinstance(report["attack_chains"], list)
        assert isinstance(report["recommendations"], list)

    def test_empty_state_graceful(self):
        report = run_pipeline({}, "")
        assert report["asset_graph"]["total_nodes"] == 1
        assert report["crown_jewels"] == []
        assert report["attack_chains"] == []

    def test_override_crown_jewels(self):
        report = run_pipeline(_sample_state(), "http://target.test", crown_jewels=["j1", "j2"])
        assert report["crown_jewels"] == ["j1", "j2"]


def _subdomain_state():
    state = _sample_state()
    state["phases"]["recon"]["subdomains"] = {
        "root_domain": "target.test",
        "resolved": [{"domain": "api.target.test", "ip": "10.0.0.5"}],
        "http_reachable": [
            {"domain": "api.target.test", "status": 200, "title": "API",
             "server": "nginx", "tech": ["https"]},
            {"domain": "admin.target.test", "status": 200, "title": "Admin",
             "server": "nginx", "tech": []},
        ],
    }
    state["phases"]["crawl"]["endpoints"]["/v1/users"] = {
        "url": "http://api.target.test/v1/users",
        "methods": ["GET"],
        "params": [],
    }
    return state


class TestCrossHost:
    def test_subdomain_host_nodes_added(self):
        g = build_asset_graph(_subdomain_state(), "http://target.test")
        assert host_id("api.target.test") in g.nodes
        assert host_id("admin.target.test") in g.nodes

    def test_subdomain_edges_connect_to_parent(self):
        g = build_asset_graph(_subdomain_state(), "http://target.test")
        assert host_id("target.test") in g.adj.get(host_id("api.target.test"), set())

    def test_endpoint_on_subdomain_wired_to_its_host(self):
        g = build_asset_graph(_subdomain_state(), "http://target.test")
        ep = endpoint_id("http://api.target.test/v1/users")
        assert ep in g.nodes
        assert g.nodes[ep].host == "api.target.test"
        assert host_id("api.target.test") in g.adj.get(ep, set())

    def test_bfs_crosses_hosts(self):
        g = build_asset_graph(_subdomain_state(), "http://target.test")
        goal = endpoint_id("http://api.target.test/v1/users")
        paths = g.bfs([host_id("target.test")], [goal])
        assert paths
        assert paths[0][-1] == goal
        assert host_id("api.target.test") in paths[0]

    def test_same_host_interconnect_still_per_host(self):
        g = build_asset_graph(_subdomain_state(), "http://target.test")
        a = endpoint_id("http://target.test/admin")
        b = endpoint_id("http://target.test/login")
        assert b in g.adj.get(a, set())
        sub = endpoint_id("http://api.target.test/v1/users")
        assert sub not in g.adj.get(a, set())

