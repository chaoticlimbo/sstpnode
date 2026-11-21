"""chaoticlimbo/gate 的 SSTP 节点流水线（单脚本，三步）。

流程：
  1. 收集：从节点池（GeorgeXie2333/vpngate-list-mirror 的 pool/servers.json）
     拉取全部节点，取带 TCP 探测端口的条目，转成 SSTP 链接、去重，
     写 node-collect.txt（一行一个 sstp:// 链接）。
  2. 检测：把 node-collect.txt 里的节点逐个送 check.socks5.lzjbaby.com
     检测，每个节点的完整检测结果写 node-tests.csv：一行一个节点，
     检测站返回的字段原样展开成列（嵌套对象用 . 连接，如 exit.country），
     不改名、不丢字段，行序与 node-collect.txt 一一对应。
  3. 成品：检测通过（success 为真）的节点写 node.txt，
     纯 sstp:// 一行一个，不限数量，按检测延迟 responseTime 升序。

配置全部走环境变量，见 Config 与 README.md。
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

REPO_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_POOL_URL = "https://raw.githubusercontent.com/GeorgeXie2333/vpngate-list-mirror/main/pool/servers.json"
DEFAULT_CHECK_BASE = "https://check.socks5.lzjbaby.com"
SSTP_USERNAME = "vpn"
SSTP_PASSWORD = "vpn"


def log(tag: str, message: str) -> None:
    print(f"[{tag}] {message}", flush=True)


# ---------------------------------------------------------------------------
# 配置（全部来自环境变量）
# ---------------------------------------------------------------------------
def _env_str(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        log("CONFIG", f"环境变量 {name}={raw!r} 不是整数，使用默认值 {default}")
        return default


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(minimum, float(raw))
    except ValueError:
        log("CONFIG", f"环境变量 {name}={raw!r} 不是数字，使用默认值 {default}")
        return default


@dataclass(frozen=True)
class Config:
    pool_url: str
    check_base: str
    collect_file: str
    tests_file: str
    node_file: str
    concurrency: int
    check_timeout: float
    deadline_s: float
    max_test_nodes: int
    http_timeout: float

    @classmethod
    def load(cls) -> "Config":
        return cls(
            pool_url=_env_str("POOL_URL", DEFAULT_POOL_URL),
            check_base=_env_str("CHECK_BASE", DEFAULT_CHECK_BASE).rstrip("/"),
            collect_file=_env_str("COLLECT_FILE", os.path.join(REPO_DIR, "node-collect.txt")),
            tests_file=_env_str("TESTS_FILE", os.path.join(REPO_DIR, "node-tests.csv")),
            node_file=_env_str("NODE_FILE", os.path.join(REPO_DIR, "node.txt")),
            concurrency=_env_int("CHECK_CONCURRENCY", 20, minimum=1),
            check_timeout=_env_float("CHECK_TIMEOUT", 30.0, minimum=1.0),
            deadline_s=_env_float("CHECK_DEADLINE", 3000.0, minimum=30.0),
            max_test_nodes=_env_int("MAX_TEST_NODES", 0),
            http_timeout=_env_float("HTTP_TIMEOUT", 60.0, minimum=5.0),
        )


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def normalize_host(host: str) -> str:
    """主机名归一化：去空白、转小写、无域名后缀时补 .opengw.net。"""
    host = host.strip().lower()
    if host and "." not in host:
        host = f"{host}.opengw.net"
    return host


def sstp_link(host: str, port: int) -> str:
    return f"sstp://{SSTP_USERNAME}:{SSTP_PASSWORD}@{host}:{port}"


def candidate_of(host: str, port: int) -> str:
    return f"{SSTP_USERNAME}:{SSTP_PASSWORD}@{host}:{port}"


def make_session(pool_size: int = 32) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=2,
        connect=2,
        read=2,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=pool_size, pool_maxsize=pool_size)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "gate-sstp-pipeline/1.0"})
    return session


def atomic_write_text(path: str, text: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp_path = f"{path}.tmp-{os.getpid()}"
    with open(tmp_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp_path, path)


def join_lines(lines: Iterable[str]) -> str:
    lines = list(lines)
    return "\n".join(lines) + "\n" if lines else ""


def flatten_result(result: dict[str, Any], prefix: str = "") -> dict[str, str]:
    """把检测结果按原字段展开成一层：嵌套 dict 用 . 连接键名，不改名、不丢字段。

    bool 写成 true/false（与检测站 JSON 一致），None 写空，其余转字符串；
    极少出现的 list 用 JSON 文本兜底。
    """
    flat: dict[str, str] = {}
    for key, value in result.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(flatten_result(value, prefix=f"{name}."))
        elif isinstance(value, bool):
            flat[name] = "true" if value else "false"
        elif value is None:
            flat[name] = ""
        elif isinstance(value, (list, tuple)):
            flat[name] = json.dumps(value, ensure_ascii=False)
        else:
            flat[name] = str(value)
    return flat


def write_tests_csv(path: str, results: list[dict[str, Any]]) -> int:
    """全部检测结果写成 CSV：一行一个节点，列为所有展开字段的并集（按首次出现顺序）。"""
    rows = [flatten_result(r) for r in results]
    columns: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                columns.append(key)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    atomic_write_text(path, buffer.getvalue())
    return len(rows)


# ---------------------------------------------------------------------------
# 第 1 步：收集节点池
# ---------------------------------------------------------------------------
def _valid_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.strip().isdigit():
        port = int(value.strip())
    else:
        return None
    return port if 1 <= port <= 65535 else None


def _to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def parse_pool_json(data: Any) -> list[tuple[str, int, int | None]]:
    """解析节点池 servers.json，返回 [(host, port, ping)]。

    只保留带合法 probe_targets 端口的 TCP 条目；不排除任何国家。
    """
    if isinstance(data, dict):
        servers = data.get("servers")
    elif isinstance(data, list):
        servers = data
    else:
        servers = None
    if not isinstance(servers, list):
        return []

    nodes: list[tuple[str, int, int | None]] = []
    for server in servers:
        if not isinstance(server, dict):
            continue
        host = normalize_host(str(server.get("hostname") or ""))
        ip = str(server.get("ip") or "").strip()
        if not host or not ip:
            continue
        port = None
        targets = server.get("probe_targets")
        if isinstance(targets, list):
            for target in targets:
                if isinstance(target, dict):
                    port = _valid_port(target.get("port"))
                    if port is not None:
                        break
        if port is None:
            continue
        nodes.append((host, port, _to_int(server.get("ping_ms"))))
    return nodes


def build_collect_lines(nodes: Iterable[tuple[str, int, int | None]]) -> list[str]:
    """转 SSTP 链接：按 (host, port) 去重保留首次，再按 ping 升序（None 最后）、host 排序。"""
    seen: set[tuple[str, int]] = set()
    unique: list[tuple[str, int, int | None]] = []
    for host, port, ping in nodes:
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        unique.append((host, port, ping))
    unique.sort(key=lambda item: (item[2] is None, item[2] or 0, item[0], item[1]))
    return [sstp_link(host, port) for host, port, _ in unique]


# ---------------------------------------------------------------------------
# 第 2 步：检测 node-collect.txt 里的节点
# ---------------------------------------------------------------------------
def parse_node_lines(text: str) -> tuple[list[tuple[str, int]], int]:
    """解析节点名单文本，返回 ([(host, port)], 坏行数)。

    每行接受三种写法：sstp://vpn:vpn@host:port、vpn:vpn@host:port、host:port。
    空行与 # 注释行跳过；无法解析的行跳过并计数；去重保留首次出现顺序。
    """
    nodes: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    bad_lines = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        rest = line
        if rest.lower().startswith("sstp://"):
            rest = rest[len("sstp://"):]
        if "://" in rest:
            bad_lines += 1
            continue
        hostport = rest.rsplit("@", 1)[-1].strip()
        host_raw, sep, port_raw = hostport.rpartition(":")
        host = normalize_host(host_raw) if sep else ""
        port = _valid_port(port_raw.strip()) if sep else None
        if not host or port is None:
            bad_lines += 1
            continue
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        nodes.append(key)
    return nodes, bad_lines


def make_stub(host: str, port: int, error: str) -> dict[str, Any]:
    """与检测站相同形状的失败存根：本地请求出错时也不丢节点、不改格式。"""
    return {
        "candidate": candidate_of(host, port),
        "type": "sstp",
        "username": SSTP_USERNAME,
        "password": SSTP_PASSWORD,
        "hostname": host,
        "port": port,
        "link": sstp_link(host, port),
        "success": False,
        "error": error,
    }


def check_one(
    session: requests.Session,
    base: str,
    host: str,
    port: int,
    timeout: float,
) -> dict[str, Any]:
    """检测单个节点：成功返回检测站的原始 JSON（不增删字段），失败返回存根。"""
    candidate = candidate_of(host, port)
    url = f"{base}/check?sstp={quote(candidate, safe='')}"
    try:
        resp = session.get(url, timeout=timeout)
    except requests.RequestException as exc:
        return make_stub(host, port, f"请求异常: {type(exc).__name__}: {exc}")
    if resp.status_code != 200:
        return make_stub(host, port, f"HTTP {resp.status_code}")
    try:
        payload = resp.json()
    except ValueError:
        return make_stub(host, port, "响应不是合法 JSON")
    if not isinstance(payload, dict):
        return make_stub(host, port, "响应 JSON 不是对象")
    return payload


def check_all(
    nodes: list[tuple[str, int]],
    session: requests.Session,
    cfg: Config,
) -> list[dict[str, Any]]:
    """并发检测，结果按输入顺序回填；超过整体截止时间未测的节点用存根补齐。"""
    results: list[dict[str, Any] | None] = [None] * len(nodes)
    if not nodes:
        return []
    deadline = time.monotonic() + cfg.deadline_s
    with ThreadPoolExecutor(max_workers=cfg.concurrency) as pool:
        future_to_idx = {
            pool.submit(check_one, session, cfg.check_base, host, port, cfg.check_timeout): idx
            for idx, (host, port) in enumerate(nodes)
        }
        try:
            remaining = max(0.0, deadline - time.monotonic())
            for future in as_completed(future_to_idx, timeout=remaining):
                idx = future_to_idx[future]
                host, port = nodes[idx]
                try:
                    results[idx] = future.result()
                except Exception as exc:  # noqa: BLE001 - check_one 本应不抛，双保险
                    results[idx] = make_stub(host, port, f"检测异常: {type(exc).__name__}: {exc}")
        except TimeoutError:
            log("CHECK", f"已到整体截止时间 {cfg.deadline_s:.0f}s，未测节点将标记为未检测")
        for future in future_to_idx:
            future.cancel()
    filled: list[dict[str, Any]] = []
    for idx, (host, port) in enumerate(nodes):
        result = results[idx]
        if result is None:
            result = make_stub(host, port, f"超过整体截止时间 {cfg.deadline_s:.0f}s，未检测")
        filled.append(result)
    return filled


# ---------------------------------------------------------------------------
# 第 3 步：成品
# ---------------------------------------------------------------------------
def _response_time(result: dict[str, Any]) -> float | None:
    value = result.get("responseTime")
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def build_node_lines(pairs: list[tuple[tuple[str, int], dict[str, Any]]]) -> list[str]:
    """从 ((host, port), result) 里挑成功的，按 responseTime 升序（缺失排最后）。"""
    passed: list[tuple[str, int, float | None]] = []
    for (host, port), result in pairs:
        if result.get("success"):
            passed.append((host, port, _response_time(result)))
    passed.sort(key=lambda item: (item[2] is None, item[2] or 0.0, item[0], item[1]))
    return [sstp_link(host, port) for host, port, _ in passed]


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def _pool_server_count(data: Any) -> int:
    if isinstance(data, dict) and isinstance(data.get("servers"), list):
        return len(data["servers"])
    if isinstance(data, list):
        return len(data)
    return 0


def main() -> int:
    cfg = Config.load()
    session = make_session(pool_size=cfg.concurrency)
    log("CONFIG", f"节点池: {cfg.pool_url}")
    log("CONFIG", f"检测站: {cfg.check_base}，并发 {cfg.concurrency}，单节点超时 {cfg.check_timeout:.0f}s")

    # ---- 第 1 步：收集 ----
    try:
        resp = session.get(cfg.pool_url, timeout=cfg.http_timeout)
        resp.raise_for_status()
        pool_data = resp.json()
    except Exception as exc:  # noqa: BLE001
        log("POOL", f"拉取或解析节点池失败 ({cfg.pool_url}): {exc}")
        return 2
    pool_total = _pool_server_count(pool_data)
    pool_nodes = parse_pool_json(pool_data)
    collect_lines = build_collect_lines(pool_nodes)
    log("POOL", f"池子总数 {pool_total}，TCP 候选 {len(pool_nodes)}，去重后 {len(collect_lines)}")
    if not collect_lines:
        log("POOL", "节点池没有解析出任何 TCP 节点，拒绝继续")
        return 2
    atomic_write_text(cfg.collect_file, join_lines(collect_lines))
    log("POOL", f"已写 {cfg.collect_file}（{len(collect_lines)} 行）")

    # ---- 第 2 步：检测（读回刚写的 node-collect.txt，保证测的就是文件里的节点） ----
    with open(cfg.collect_file, encoding="utf-8", errors="replace") as fh:
        collect_text = fh.read()
    targets_all, bad_lines = parse_node_lines(collect_text)
    log("COLLECT", f"待测节点解析出 {len(targets_all)} 个，坏行 {bad_lines}")
    if not targets_all:
        log("COLLECT", "node-collect.txt 里没有可检测的节点，拒绝继续")
        return 2

    targets = targets_all
    if cfg.max_test_nodes > 0:
        targets = targets_all[: cfg.max_test_nodes]
        log("CHECK", f"MAX_TEST_NODES={cfg.max_test_nodes}，本次只测前 {len(targets)} 个")

    check_started = time.time()
    results = check_all(targets, session, cfg)
    elapsed = time.time() - check_started
    success_count = sum(1 for r in results if r.get("success"))
    failed_count = len(results) - success_count
    log("CHECK", f"检测完成：待测 {len(targets)}，成功 {success_count}，失败 {failed_count}，用时 {elapsed:.1f}s")

    written = write_tests_csv(cfg.tests_file, results)
    log("CHECK", f"已写 {cfg.tests_file}（{written} 行）")

    # ---- 第 3 步：成品 ----
    node_lines = build_node_lines(list(zip(targets, results)))
    atomic_write_text(cfg.node_file, join_lines(node_lines))
    log("RESULT", f"已写 {cfg.node_file}（{len(node_lines)} 行）")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if summary_path:
        summary = (
            "## SSTP Node Pipeline\n\n"
            f"- 节点池总数：{pool_total}（TCP 候选 {len(pool_nodes)}，去重后 {len(collect_lines)}）\n"
            f"- 待测节点：{len(targets)}\n"
            f"- 检测成功：{success_count}\n"
            f"- 检测失败：{failed_count}\n"
            f"- 成品 node.txt：{len(node_lines)} 行\n"
        )
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(summary)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("INTERRUPT", "已被中断")
        sys.exit(2)
