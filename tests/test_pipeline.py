import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

import pipeline
from pipeline import build_collect_lines, build_node_lines, parse_node_lines, parse_pool_json


# ---------------------------------------------------------------------------
# parse_pool_json
# ---------------------------------------------------------------------------
def test_parse_pool_json_reads_tcp_and_skips_others():
    data = {
        "kind": "vpngate-pool",
        "servers": [
            {
                "hostname": "vpn111",
                "ip": "203.0.113.1",
                "ping_ms": 30,
                "score": 100,
                "probe_targets": [{"ip": "203.0.113.1", "port": 995}],
            },
            {  # UDP：没有 probe_targets，跳过
                "hostname": "vpn222",
                "ip": "203.0.113.2",
                "ping_ms": 10,
                "probe_targets": [],
            },
            {  # 缺 hostname，跳过
                "ip": "203.0.113.3",
                "probe_targets": [{"ip": "203.0.113.3", "port": 443}],
            },
            {  # 缺 ip，跳过
                "hostname": "vpn333",
                "probe_targets": [{"ip": "203.0.113.4", "port": 443}],
            },
            {  # 端口非法，跳过
                "hostname": "vpn444",
                "ip": "203.0.113.5",
                "probe_targets": [{"ip": "203.0.113.5", "port": 70000}],
            },
            "not-a-dict",
        ],
    }
    assert parse_pool_json(data) == [("vpn111.opengw.net", 995, 30)]


def test_parse_pool_json_accepts_bare_list_and_string_port():
    data = [
        {
            "hostname": "vpn.example.com",
            "ip": "198.51.100.1",
            "probe_targets": [{"ip": "198.51.100.1", "port": "8443"}],
        }
    ]
    # 主机名已有域名后缀时不补 .opengw.net；ping 缺失为 None
    assert parse_pool_json(data) == [("vpn.example.com", 8443, None)]


def test_parse_pool_json_bad_top_level():
    assert parse_pool_json(42) == []
    assert parse_pool_json({"servers": "nope"}) == []
    assert parse_pool_json({}) == []


# ---------------------------------------------------------------------------
# build_collect_lines
# ---------------------------------------------------------------------------
def test_build_collect_lines_dedupes_and_sorts():
    nodes = [
        ("b.opengw.net", 443, 50),
        ("a.opengw.net", 443, None),
        ("b.opengw.net", 443, 10),  # 重复 (host, port)，保留首次出现（ping 50）
        ("c.opengw.net", 443, 10),
    ]
    assert build_collect_lines(nodes) == [
        "sstp://vpn:vpn@c.opengw.net:443",
        "sstp://vpn:vpn@b.opengw.net:443",
        "sstp://vpn:vpn@a.opengw.net:443",  # ping 为 None 排最后
    ]


# ---------------------------------------------------------------------------
# parse_node_lines
# ---------------------------------------------------------------------------
def test_parse_node_lines_three_forms_comments_and_bad_lines():
    text = "\n".join(
        [
            "# 待测名单",
            "",
            "sstp://vpn:vpn@host-b.opengw.net:995",
            "vpn:vpn@host-a.opengw.net:443",
            "host-c:8443",
            "这一行是坏的",
            "host-d.opengw.net:notaport",
            "sstp://vpn:vpn@host-b.opengw.net:995",  # 重复，去重
        ]
    )
    nodes, bad = parse_node_lines(text)
    assert nodes == [
        ("host-b.opengw.net", 995),
        ("host-a.opengw.net", 443),
        ("host-c.opengw.net", 8443),  # 裸主机名补 .opengw.net
    ]
    assert bad == 2


# ---------------------------------------------------------------------------
# build_node_lines
# ---------------------------------------------------------------------------
def test_build_node_lines_filters_and_sorts_by_response_time():
    pairs = [
        (("slow.opengw.net", 443), {"success": True, "responseTime": 900}),
        (("fail.opengw.net", 443), {"success": False, "error": "boom"}),
        (("fast.opengw.net", 443), {"success": True, "responseTime": 120}),
        (("unknown.opengw.net", 443), {"success": True}),  # 无 responseTime 排最后
    ]
    assert build_node_lines(pairs) == [
        "sstp://vpn:vpn@fast.opengw.net:443",
        "sstp://vpn:vpn@slow.opengw.net:443",
        "sstp://vpn:vpn@unknown.opengw.net:443",
    ]


# ---------------------------------------------------------------------------
# check_one 的存根行为（本地请求出错也不抛异常、不丢节点）
# ---------------------------------------------------------------------------
class _BoomSession:
    def get(self, url, timeout=None):
        raise requests.ConnectionError("refused")


class _Http503Session:
    class _Resp:
        status_code = 503

        def json(self):
            return {}

    def get(self, url, timeout=None):
        return self._Resp()


def test_check_one_network_error_becomes_stub():
    result = pipeline.check_one(_BoomSession(), "https://checker.example", "h.opengw.net", 443, 5.0)
    assert result["success"] is False
    assert result["hostname"] == "h.opengw.net"
    assert result["port"] == 443
    assert result["link"] == "sstp://vpn:vpn@h.opengw.net:443"
    assert "请求异常" in result["error"]


def test_check_one_http_error_becomes_stub():
    result = pipeline.check_one(_Http503Session(), "https://checker.example", "h.opengw.net", 443, 5.0)
    assert result["success"] is False
    assert result["error"] == "HTTP 503"


# ---------------------------------------------------------------------------
# 集成测试：假服务器同时供池子 JSON 和 /check
# ---------------------------------------------------------------------------
POOL = {
    "kind": "vpngate-pool",
    "server_count": 4,
    "servers": [
        {
            "hostname": "host-a",
            "ip": "203.0.113.1",
            "ping_ms": 30,
            "score": 100,
            "probe_targets": [{"ip": "203.0.113.1", "port": 443}],
        },
        {
            "hostname": "host-b",
            "ip": "203.0.113.2",
            "ping_ms": 10,
            "score": 200,
            "probe_targets": [{"ip": "203.0.113.2", "port": 995}],
        },
        {"hostname": "host-u", "ip": "203.0.113.3", "ping_ms": 5, "probe_targets": []},
        {"ip": "203.0.113.4", "probe_targets": [{"ip": "203.0.113.4", "port": 443}]},
    ],
}

CHECK_BEHAVIOR = {
    "host-b.opengw.net": (True, 300),
    "host-a.opengw.net": (True, 100),
    "host-c.opengw.net": (False, None),
}


def build_handler() -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server 接口
            parsed = urlsplit(self.path)
            if parsed.path == "/pool":
                body, ctype = json.dumps(POOL).encode("utf-8"), "application/json"
            elif parsed.path == "/check":
                candidate = parse_qs(parsed.query).get("sstp", [""])[0]
                hostport = candidate.rsplit("@", 1)[-1]
                host, _, port_raw = hostport.rpartition(":")
                port = int(port_raw)
                success, rt = CHECK_BEHAVIOR.get(host, (False, None))
                payload = {
                    "candidate": candidate,
                    "type": "sstp",
                    "username": "vpn",
                    "password": "vpn",
                    "hostname": host,
                    "port": port,
                    "link": f"sstp://{candidate}",
                    "success": success,
                    "colo": "TEST",
                }
                if success:
                    payload["responseTime"] = rt
                    payload["exit"] = {"ip": "198.51.100.7", "country_code": "JP"}
                else:
                    payload["error"] = "boom"
                body, ctype = json.dumps(payload).encode("utf-8"), "application/json"
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # noqa: A003 - 静默
            pass

    return Handler


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), build_handler())
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_main_end_to_end(server, monkeypatch, tmp_path):
    collect = tmp_path / "node-collect.txt"
    tests = tmp_path / "node-tests.txt"
    node = tmp_path / "node.txt"
    monkeypatch.setenv("POOL_URL", f"{server}/pool")
    monkeypatch.setenv("CHECK_BASE", server)
    monkeypatch.setenv("COLLECT_FILE", str(collect))
    monkeypatch.setenv("TESTS_FILE", str(tests))
    monkeypatch.setenv("NODE_FILE", str(node))
    monkeypatch.setenv("CHECK_CONCURRENCY", "4")
    monkeypatch.setenv("CHECK_TIMEOUT", "5")
    monkeypatch.setenv("CHECK_DEADLINE", "60")
    monkeypatch.setenv("HTTP_TIMEOUT", "5")
    monkeypatch.delenv("MAX_TEST_NODES", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    assert pipeline.main() == 0

    # 第 1 步：只含 TCP 节点，按 ping 升序（host-b 10 < host-a 30）
    assert collect.read_text(encoding="utf-8").splitlines() == [
        "sstp://vpn:vpn@host-b.opengw.net:995",
        "sstp://vpn:vpn@host-a.opengw.net:443",
    ]

    # 第 2 步：一行一条 JSON，顺序与 node-collect.txt 一致
    test_rows = [json.loads(line) for line in tests.read_text(encoding="utf-8").splitlines()]
    assert [row["hostname"] for row in test_rows] == [
        "host-b.opengw.net",
        "host-a.opengw.net",
    ]
    assert [row["success"] for row in test_rows] == [True, True]
    assert test_rows[0]["exit"]["country_code"] == "JP"

    # 第 3 步：只含成功节点，按 responseTime 升序（host-a 100 < host-b 300）
    assert node.read_text(encoding="utf-8").splitlines() == [
        "sstp://vpn:vpn@host-a.opengw.net:443",
        "sstp://vpn:vpn@host-b.opengw.net:995",
    ]
