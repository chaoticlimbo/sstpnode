#!/usr/bin/env python3
"""VPN Gate SSTP 节点检测流水线（模板仓库）。

流程:
1. 从 funcra/vg-mirror/servers_history/info.json 动态获取全部历史 CSV 节点
2. 只保留带 TCP 入口且未被排除（默认排除俄罗斯 RU）的 SSTP 节点
3. 去重 → 按 Ping 预排序 →（可选）截断
4. 并发调用检测 Worker
5. 按检测延迟（latency_ms）升序筛选前 50 个有效成功节点用于发布
6. 合并静态优选域名与优选 API 端点
7. 生成 public/data.json + public/index.html + public/nodes.txt

配置全部来自环境变量。模板仓库约定：用户只需在仓库里配置 Secret `DOMAIN`，
工作流会拼出检测地址；本地运行时可以直接设置 CHECK_WORKER。
"""

from __future__ import annotations

import base64
import csv
import html
import io
import json
import math
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import quote, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

SCHEMA_VERSION = 1
DEFAULT_PUBLISH_TOP_N = 50

DEFAULT_VG_HISTORY_INFO_URL = (
    "https://raw.githubusercontent.com/funcra/vg-mirror/main/servers_history/info.json"
)
DEFAULT_OPTIMAL_API = ""

# 排除俄罗斯（RU）
DEFAULT_BLOCKED_COUNTRY_CODES = frozenset({"RU"})
COUNTRY_NAME_TO_CODE = {
    "RU": "RU",
    "RUS": "RU",
    "RUSSIA": "RU",
    "RUSSIAN FEDERATION": "RU",
    "俄罗斯": "RU",
}

# 占位符检测：命中任意一个就认为用户还没配置
PLACEHOLDER_MARKERS = ("你的", "YOUR_", "YOUR-", "example.com", "yourdomain")

# 静态优选域名池（可用 EDGE_HOSTS 整体覆盖）
DEFAULT_EDGE_HOSTS = [
    "saas.sin.fan:443",
    "www.mfyx.cn:443",
    "cf.nyanya.moe:443",
    "cf.877774.xyz:443",
    "cdn.204910.best:443",
    "cdn.ctn32.us.kg:443",
    "p.etime.vip:443",
    "cmcc.vvvv.ee:443",
    "cfsaas.080112.xyz:443",
    "cdn.aneko.ink:443",
    "hk.cf.3666888.xyz:443",
    "best.hzample.kdns.fr:443",
    "ctsg.cfyx.aliyun.20237737.xyz:443",
    "china-unicom.cname.cloudflare.468123.xyz:443",
]

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASEWEB",
]

RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6|tcp-client)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+(\S+)\s+(\d+)", re.M)


# ---------------------------------------------------------------------------
# 日志与错误
# ---------------------------------------------------------------------------
_section: str | None = None


def log(section: str, msg: str = "") -> None:
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)


class ConfigError(Exception):
    """配置缺失或非法；main 会把它转成可读的失败信息。"""


def die(section: str, msg: str, code: int = 2) -> None:
    log(section, f"[失败] {msg}")
    raise SystemExit(code)


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} 需要是整数，当前值：{raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} 不能小于 {minimum}，当前值：{value}")
    return value


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} 需要是数字，当前值：{raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} 不能小于 {minimum}，当前值：{value}")
    return value


def parse_blocked_countries(raw: str | None) -> frozenset[str]:
    """解析要排除的国家代码集合，默认仅排除俄罗斯(RU)。"""
    if not raw or not raw.strip():
        return DEFAULT_BLOCKED_COUNTRY_CODES
    codes: set[str] = set()
    for part in raw.split(","):
        token = part.strip().upper()
        if not token:
            continue
        mapped = COUNTRY_NAME_TO_CODE.get(token, token)
        if len(mapped) == 2 and mapped.isalpha():
            codes.add(mapped)
    return frozenset(codes) if codes else DEFAULT_BLOCKED_COUNTRY_CODES


def resolve_country_code(country_code: str | None, country_name: str | None = None) -> str:
    """将国家代码或国家名称归一化为两位国家代码（如 RU）。"""
    code = (country_code or "").strip().upper()
    if code in COUNTRY_NAME_TO_CODE:
        return COUNTRY_NAME_TO_CODE[code]
    if code:
        return code
    name = (country_name or "").strip().upper()
    if name in COUNTRY_NAME_TO_CODE:
        return COUNTRY_NAME_TO_CODE[name]
    return ""


def is_blocked_country(
    country_code: str | None,
    country_name: str | None = None,
    blocked_codes: Iterable[str] = DEFAULT_BLOCKED_COUNTRY_CODES,
) -> bool:
    """判断节点是否属于被排除的国家/地区（默认排除 RU）。"""
    blocked = frozenset(c.upper() for c in blocked_codes)
    resolved = resolve_country_code(country_code, country_name)
    return bool(resolved and resolved in blocked)


def normalize_worker_base(raw: str) -> str:
    """把 CHECK_WORKER / DOMAIN 归一化成以 `sstp=vpn:vpn@` 结尾的检测地址前缀。"""
    value = (raw or "").strip()
    if not value:
        raise ConfigError(
            "未配置检测 Worker 地址。请在仓库 Settings → Secrets and variables → Actions "
            "添加 Secret `DOMAIN`（只填 host，例如 abc.workers.dev），"
            "或本地运行时设置环境变量 CHECK_WORKER。"
        )
    lowered = value.lower()
    if any(marker.lower() in lowered for marker in PLACEHOLDER_MARKERS):
        raise ConfigError(
            "检测地址仍是占位符。请在仓库 Settings → Secrets and variables → Actions "
            "添加 Secret `DOMAIN`（只填 host，例如 abc.workers.dev），工作流会自动拼出检测地址。"
        )
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value):
        value = "https://" + value
    parts = urlsplit(value)
    if not parts.netloc:
        raise ConfigError(f"无法解析检测 Worker 地址：{value!r}")

    path = parts.path.rstrip("/")
    if not path.endswith("/check"):
        path = path + "/check"

    query = parts.query
    if "sstp=" not in query:
        query = (query + "&" if query else "") + "sstp=vpn:vpn@"
    else:
        params = [item for item in query.split("&") if item]
        for i, item in enumerate(params):
            if item.startswith("sstp="):
                target = item[len("sstp="):]
                if "@" not in target:
                    params[i] = "sstp=" + (target or "vpn:vpn") + "@"
        query = "&".join(params)
    return f"{parts.scheme}://{parts.netloc}{path}?{query}"


def normalize_endpoint(raw: str) -> str | None:
    """把 `IP:端口` / 域名 / IPv6 归一化成可用的 `host:port` 或 `[v6]:port`。"""
    text = (raw or "").strip()
    if not text:
        return None
    text = text.split("#", 1)[0].strip().split("/", 1)[0].strip()
    if not text:
        return None

    host: str
    port: str
    if text.startswith("["):
        match = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?", text)
        if not match:
            return None
        host = match.group(1)
        port = match.group(2) or "443"
    else:
        colons = text.count(":")
        if colons == 0:
            host, port = text, "443"
        elif colons == 1:
            host, port = text.rsplit(":", 1)
        else:  # 裸 IPv6
            host, port = text, "443"
        if colons <= 1 and not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            return None

    try:
        port_number = int(port)
    except ValueError:
        return None
    if not 1 <= port_number <= 65535:
        return None
    if ":" in host:
        return f"[{host}]:{port_number}"
    return f"{host}:{port_number}"


def parse_edge_hosts(raw: str) -> list[str]:
    endpoints: list[str] = []
    seen: set[str] = set()
    for item in raw.split(","):
        endpoint = normalize_endpoint(item)
        if endpoint and endpoint not in seen:
            seen.add(endpoint)
            endpoints.append(endpoint)
    return endpoints


def derive_nodes_url() -> str:
    """从 GITHUB_REPOSITORY 推导 nodes.txt 地址；本地运行回退占位。"""
    explicit = os.environ.get("NODES_URL", "").strip()
    if explicit:
        return explicit
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if "/" in repo:
        owner, name = repo.split("/", 1)
        if owner and name:
            return f"https://{owner}.github.io/{name}/nodes.txt"
    return "https://<owner>.github.io/<repo>/nodes.txt"


@dataclass(frozen=True)
class Config:
    worker_base: str
    concurrency: int
    check_timeout: float
    deadline_s: float
    http_timeout: float
    max_check_nodes: int
    public_dir: str
    template_html: str
    edge_hosts: tuple[str, ...]
    optimal_api: str
    nodes_url: str
    min_success_ratio: float
    max_residential_per_country: int
    max_datacenter_per_country: int
    vg_history_info_url: str = DEFAULT_VG_HISTORY_INFO_URL
    vpngate_api: str = ""
    vpngate_mirror: str = ""
    blocked_countries: frozenset[str] = DEFAULT_BLOCKED_COUNTRY_CODES
    publish_top_n: int = DEFAULT_PUBLISH_TOP_N

    @classmethod
    def load(cls) -> "Config":
        raw_worker = os.environ.get("CHECK_WORKER", "").strip()
        if not raw_worker:
            domain = os.environ.get("DOMAIN", "").strip()
            if domain:
                raw_worker = f"https://{domain}/check?sstp=vpn:vpn@"
        worker_base = normalize_worker_base(raw_worker)

        static_raw = os.environ.get("HOSTS_ENTRY", "").strip()
        if not static_raw:
            static_raw = os.environ.get("EDGE_HOSTS", "").strip()
        edge_hosts = parse_edge_hosts(static_raw) if static_raw else []
        if not edge_hosts:
            edge_hosts = [h for h in (normalize_endpoint(x) for x in DEFAULT_EDGE_HOSTS) if h]

        info_url = (
            os.environ.get("VG_HISTORY_INFO_URL", "").strip()
            or os.environ.get("VPNGATE_HISTORY_INFO_URL", "").strip()
            or DEFAULT_VG_HISTORY_INFO_URL
        )

        return cls(
            worker_base=worker_base,
            concurrency=_env_int("CHECK_CONCURRENCY", 32, minimum=1),
            check_timeout=_env_float("CHECK_TIMEOUT", 25.0, minimum=1.0),
            deadline_s=_env_float("CHECK_DEADLINE", 1200.0, minimum=30.0),
            http_timeout=_env_float("HTTP_TIMEOUT", 60.0, minimum=5.0),
            max_check_nodes=_env_int("MAX_CHECK_NODES", 0),
            public_dir=os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public")),
            template_html=os.path.join(REPO_DIR, "web", "index.html"),
            edge_hosts=tuple(edge_hosts),
            optimal_api=os.environ.get("OPTIMAL_API", DEFAULT_OPTIMAL_API),
            nodes_url=derive_nodes_url(),
            min_success_ratio=_env_float("MIN_SUCCESS_RATIO", 0.0, minimum=0.0),
            max_residential_per_country=_env_int("MAX_RESIDENTIAL_PER_COUNTRY", 20),
            max_datacenter_per_country=_env_int("MAX_DATACENTER_PER_COUNTRY", 10),
            vg_history_info_url=info_url,
            vpngate_api=os.environ.get("VPNGATE_API", "").strip(),
            vpngate_mirror=os.environ.get("VPNGATE_MIRROR", "").strip(),
            blocked_countries=parse_blocked_countries(os.environ.get("BLOCKED_COUNTRIES")),
            publish_top_n=_env_int("PUBLISH_TOP_N", DEFAULT_PUBLISH_TOP_N, minimum=1),
        )


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def make_session(pool_size: int = 32, retries: int = 2) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        pool_connections=pool_size,
        pool_maxsize=pool_size,
        max_retries=retry,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"})
    return session


# ---------------------------------------------------------------------------
# 数据抓取与解析
# ---------------------------------------------------------------------------
def _validate_history_entry(entry: Any, index: int) -> tuple[str, str]:
    if not isinstance(entry, dict):
        raise ValueError(f"historical[{index}] 不是对象")

    raw_name = entry.get("filename")
    if not isinstance(raw_name, str) or not raw_name.strip():
        raise ValueError(f"historical[{index}] 缺少有效的 filename")
    filename = raw_name.strip()
    if (
        "/" in filename
        or "\\" in filename
        or ".." in filename
        or not re.fullmatch(r"[A-Za-z0-9._-]+\.csv", filename, flags=re.IGNORECASE)
    ):
        raise ValueError(f"historical[{index}] filename 非法: {filename!r}")

    raw_url = entry.get("url")
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError(f"historical[{index}] ({filename}) 缺少有效的 url")
    url = raw_url.strip()
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"historical[{index}] ({filename}) URL 非法: {url!r}")
    if ".." in (parsed.path or ""):
        raise ValueError(f"historical[{index}] ({filename}) URL 路径包含非法跳转: {parsed.path!r}")

    return filename, url


def fetch_vpngate(cfg: Config, session: requests.Session) -> tuple[list[dict[str, Any]], str]:
    if cfg.vpngate_api and not os.environ.get("VG_HISTORY_INFO_URL", "").strip():
        log("VPN GATE", f"获取历史 CSV 数据源: {cfg.vpngate_api}")
        try:
            resp = session.get(cfg.vpngate_api, timeout=cfg.http_timeout)
            resp.raise_for_status()
            if not resp.encoding:
                resp.encoding = "utf-8"
            rows = parse_csv(resp.text)
        except Exception as exc:  # noqa: BLE001
            die("VPN GATE", f"获取或解析 CSV 数据源失败 ({cfg.vpngate_api}): {exc}")
        log("VPN GATE", f"成功获取历史 CSV 文件数: 1/1，总节点数: {len(rows)}")
        if not rows:
            die("VPN GATE", "历史 CSV 节点总数为 0")
        return rows, "funcra/vg-mirror/servers_history"

    info_url = getattr(cfg, "vg_history_info_url", "") or DEFAULT_VG_HISTORY_INFO_URL
    log("VPN GATE", f"获取历史索引: {info_url}")
    try:
        resp = session.get(info_url, timeout=cfg.http_timeout)
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        die("VPN GATE", f"请求 info.json 失败 ({info_url}): {exc}")

    try:
        info_data = resp.json()
    except Exception as exc:  # noqa: BLE001
        die("VPN GATE", f"解析 info.json 失败，JSON 格式错误: {exc}")

    if not isinstance(info_data, dict) or "historical" not in info_data:
        die("VPN GATE", "info.json 缺少 'historical' 字段或结构不是 JSON 对象")

    historical = info_data.get("historical")
    if not isinstance(historical, list) or len(historical) == 0:
        die("VPN GATE", "info.json 中的 'historical' 为空或不是非空数组")

    validated_entries: list[tuple[str, str]] = []
    for idx, item in enumerate(historical):
        try:
            validated_entries.append(_validate_history_entry(item, idx))
        except ValueError as exc:
            die("VPN GATE", f"索引条目校验失败: {exc}")

    log("VPN GATE", f"索引包含 {len(validated_entries)} 个历史 CSV 文件，开始逐一下载并解析")

    merged_rows: list[dict[str, Any]] = []
    success_files = 0

    for filename, file_url in validated_entries:
        try:
            csv_resp = session.get(file_url, timeout=cfg.http_timeout)
            csv_resp.raise_for_status()
            if not csv_resp.encoding:
                csv_resp.encoding = "utf-8"
            csv_text = csv_resp.text
        except Exception as exc:  # noqa: BLE001
            die("VPN GATE", f"下载历史 CSV 失败 [文件: {filename}, URL: {file_url}]: {exc}")

        try:
            file_rows = parse_csv(csv_text)
        except Exception as exc:  # noqa: BLE001
            die("VPN GATE", f"解析历史 CSV 失败 [文件: {filename}]: {exc}")

        success_files += 1
        merged_rows.extend(file_rows)
        log("VPN GATE", f"已解析 {filename}: {len(file_rows)} 个节点")

    log(
        "VPN GATE",
        f"成功获取历史 CSV 文件数: {success_files}/{len(validated_entries)}，总节点数: {len(merged_rows)}",
    )
    if success_files != len(validated_entries):
        die(
            "VPN GATE",
            f"历史 CSV 未全部获取成功（成功 {success_files}/{len(validated_entries)}），拒绝继续",
        )
    if not merged_rows:
        die("VPN GATE", f"已获取 {success_files} 个历史 CSV 文件，但节点总数为 0")

    return merged_rows, "funcra/vg-mirror/servers_history"


def parse_csv(text: str) -> list[dict[str, Any]]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, line in enumerate(lines):
        if line.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = [h.strip().lstrip("*").lower() for h in lines[header_idx].lstrip("#").split(",")]
    column = {name: idx for idx, name in enumerate(header) if name}

    def pick(*names: str, default: int | None = None) -> int | None:
        for name in names:
            if name in column:
                return column[name]
        return default

    idx_host = pick("hostname", default=0)
    idx_ip = pick("ip", default=1)
    idx_long = pick("countrylong", default=5)
    idx_short = pick("countryshort", default=6)
    idx_ping = pick("ping")
    idx_score = pick("score")
    idx_config = pick("openvpn_configdata_base64")
    if idx_config is None:
        idx_config = next(
            (i for i, name in enumerate(header) if "base64" in name),
            len(header) - 1,
        )

    rows: list[dict[str, Any]] = []
    for line in lines[header_idx + 1:]:
        if line.startswith(("*", "#")):
            continue
        try:
            fields = next(csv.reader(io.StringIO(line)))
        except Exception:  # noqa: BLE001 - 坏行直接跳过
            continue
        if len(fields) <= max(idx_host or 0, idx_ip or 0):
            continue

        def cell(index: int | None) -> str:
            if index is None or index >= len(fields):
                return ""
            return fields[index].strip()

        host = cell(idx_host)
        ip = cell(idx_ip)
        if not host or not ip:
            continue

        def to_int(index: int | None) -> int | None:
            raw = cell(index)
            return int(raw) if raw.isdigit() else None

        rows.append(
            {
                "host": host,
                "ip": ip,
                "country_long": cell(idx_long),
                "country_short": cell(idx_short),
                "config_b64": cell(idx_config),
                "ping": to_int(idx_ping),
                "score": to_int(idx_score),
            }
        )
    return rows


def parse_mirror_json(data: Any) -> list[dict[str, Any]]:
    """兼容保留的结构解析辅助函数（不作为运行时数据源或回退源）。"""
    servers: list[dict[str, Any]] = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict) and item.get("hostname"):
            servers.append(item)

    rows: list[dict[str, Any]] = []
    for server in servers:
        if not isinstance(server, dict):
            continue
        host = str(server.get("hostname") or server.get("host") or "").strip()
        ip = str(server.get("ip") or "").strip()
        if not host or not ip:
            continue

        def as_int(key: str) -> int | None:
            try:
                return int(str(server.get(key) or "").strip())
            except (TypeError, ValueError):
                return None

        rows.append(
            {
                "host": host,
                "ip": ip,
                "country_long": str(
                    server.get("countrylong") or server.get("country_long") or server.get("country") or ""
                ).strip(),
                "country_short": str(
                    server.get("countryshort") or server.get("country_short") or ""
                ).strip(),
                "config_b64": str(
                    server.get("openvpn_configdata_base64") or server.get("config_b64") or ""
                ).strip(),
                "ping": as_int("ping"),
                "score": as_int("score"),
            }
        )
    return rows


# ---------------------------------------------------------------------------
# 筛选 SSTP 节点
# ---------------------------------------------------------------------------
@dataclass
class Node:
    host: str
    port: int
    ip: str
    country: str
    country_code: str
    ping: int | None = None
    score: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "ping": self.ping,
            "score": self.score,
        }


def to_sstp_nodes(
    rows: Iterable[dict[str, Any]],
    blocked_countries: Iterable[str] = DEFAULT_BLOCKED_COUNTRY_CODES,
) -> list[Node]:
    blocked = frozenset(c.upper() for c in blocked_countries)
    nodes: list[Node] = []
    for row in rows:
        raw_code = (row.get("country_short") or "").strip()
        raw_country = (row.get("country_long") or "").strip()
        if is_blocked_country(raw_code, raw_country, blocked):
            continue
        resolved_code = (resolve_country_code(raw_code, raw_country) or raw_code).upper()

        config_b64 = row.get("config_b64") or ""
        if not config_b64:
            continue
        try:
            config = base64.b64decode(config_b64, validate=False).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue
        if not _PROTO_TCP_RE.search(config):
            continue
        match = _REMOTE_RE.search(config)
        if not match:
            continue
        port = int(match.group(2))
        if not 1 <= port <= 65535:
            continue

        host = (row.get("host") or "").strip().lower()
        if not host:
            continue
        if "." not in host:
            host = f"{host}.opengw.net"

        nodes.append(
            Node(
                host=host,
                port=port,
                ip=(row.get("ip") or "").strip(),
                country=raw_country,
                country_code=resolved_code,
                ping=row.get("ping"),
                score=row.get("score"),
            )
        )
    return nodes


def dedupe_nodes(nodes: Iterable[Node]) -> list[Node]:
    seen: set[tuple[str, int]] = set()
    unique: list[Node] = []
    for node in nodes:
        key = (node.host, node.port)
        if key in seen:
            continue
        seen.add(key)
        unique.append(node)
    return unique


def prioritize(nodes: list[Node]) -> list[Node]:
    """按 Ping 升序、Score 降序预排序，让抽样先测质量更好的节点。"""
    return sorted(
        nodes,
        key=lambda n: (n.ping is None, n.ping or 0, -(n.score or 0), n.host),
    )


# ---------------------------------------------------------------------------
# 分类（以 Worker 的出口信息为准，缺失时才看 Operator 关键字）
# ---------------------------------------------------------------------------
def classify_network(org: str | None, is_datacenter: bool | None) -> str:
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    upper = (org or "").upper()
    if upper:
        if any(keyword in upper for keyword in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(keyword in upper for keyword in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    return "unknown"


# ---------------------------------------------------------------------------
# 检测与延迟前 N 筛选
# ---------------------------------------------------------------------------
def _parse_valid_latency_ms(value: Any) -> float | None:
    """将 latency_ms 清洗为合法的非负有限浮点数；非法或缺失返回 None。"""
    if value is None or isinstance(value, bool):
        return None
    try:
        latency = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(latency) or latency < 0:
        return None
    return latency


def _normalize_latency_output(value: Any) -> int | float:
    latency = float(value)
    if latency.is_integer():
        return int(latency)
    return round(latency, 2)


def select_top_latency_nodes(
    results: Iterable[dict[str, Any]],
    limit: int = DEFAULT_PUBLISH_TOP_N,
) -> list[dict[str, Any]]:
    """从检测结果中筛选成功且延迟合法的节点，按延迟升序取前 limit 个用于发布。"""
    if limit <= 0:
        return []

    candidates: list[tuple[float, int, str, int, dict[str, Any]]] = []
    seen_keys: set[tuple[str, int]] = set()
    skipped_unsuccessful = 0
    skipped_invalid_latency = 0
    skipped_duplicate = 0

    for item in results:
        if not isinstance(item, dict):
            skipped_invalid_latency += 1
            continue

        if item.get("success") is not True and item.get("status") != "success":
            skipped_unsuccessful += 1
            continue

        latency = _parse_valid_latency_ms(item.get("latency_ms"))
        if latency is None:
            skipped_invalid_latency += 1
            continue

        host = str(item.get("host") or "").strip().lower()
        try:
            port = int(item.get("port") or 0)
        except (TypeError, ValueError):
            port = 0

        key = (host, port)
        if host and port > 0:
            if key in seen_keys:
                skipped_duplicate += 1
                continue
            seen_keys.add(key)

        raw_score = item.get("score")
        score_val = (
            int(raw_score)
            if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool)
            else 0
        )

        cleaned = dict(item)
        cleaned["latency_ms"] = _normalize_latency_output(latency)
        cleaned["success"] = True
        cleaned["status"] = "success"
        if not cleaned.get("link") and host and port > 0:
            cleaned["link"] = f"sstp://vpn:vpn@{host}:{port}"

        candidates.append((latency, -score_val, host, port, cleaned))

    candidates.sort(key=lambda tup: (tup[0], tup[1], tup[2], tup[3]))
    selected = [tup[4] for tup in candidates[:limit]]

    log(
        "PUBLISH FILTER",
        f"延迟有效候选 {len(candidates)} 个（跳过未成功 {skipped_unsuccessful}，"
        f"延迟无效 {skipped_invalid_latency}，重复 {skipped_duplicate}），"
        f"最终选取前 {len(selected)} 个发布（上限 {limit}）",
    )
    return selected


def check_one(
    node: Node,
    session: requests.Session,
    worker_base: str,
    timeout: float,
) -> dict[str, Any]:
    result: dict[str, Any] = node.to_dict()
    result.update(
        {
            "protocol": "sstp",
            "link": f"sstp://vpn:vpn@{node.host}:{node.port}",
            "status": "failed",
            "success": False,
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "exit": None,
            "latency_ms": None,
            "colo": None,
            "error": None,
            "worker_error": False,
            "residential": "unknown",
        }
    )
    url = worker_base + quote(f"{node.host}:{node.port}", safe="")
    try:
        response = session.get(url, timeout=timeout)
        if response.status_code != 200:
            result["error"] = f"HTTP {response.status_code}"
            result["worker_error"] = True
            return result

        payload = response.json()
        if not isinstance(payload, dict):
            result["error"] = "Invalid JSON payload"
            result["worker_error"] = True
            return result

        success = bool(payload.get("success"))
        raw_latency = _parse_valid_latency_ms(payload.get("responseTime"))
        result["success"] = success
        result["status"] = "success" if success else "failed"
        result["latency_ms"] = (
            _normalize_latency_output(raw_latency) if (success and raw_latency is not None) else None
        )
        result["colo"] = payload.get("colo")
        result["error"] = None if success else (
            payload.get("error") or payload.get("message") or "check failed"
        )

        exit_info = payload.get("exit") or {}
        if success and isinstance(exit_info, dict) and exit_info:
            asn = exit_info.get("asn") or {}
            if not isinstance(asn, dict):
                asn = {}
            org = str(asn.get("org") or asn.get("name") or "")
            result["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            result["residential"] = classify_network(org, exit_info.get("is_datacenter"))
        elif success:
            result["residential"] = "unknown"
        return result
    except Exception as exc:  # noqa: BLE001 - 单节点失败不影响整体
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["worker_error"] = True
        return result


def check_all(
    nodes: list[Node],
    session: requests.Session,
    cfg: Config,
) -> tuple[list[dict[str, Any]], int]:
    """并发检测；返回 (结果列表, 因整体超时未完成的数量)。"""
    results: list[dict[str, Any]] = []
    deadline = time.monotonic() + cfg.deadline_s
    with ThreadPoolExecutor(max_workers=cfg.concurrency) as pool:
        futures = {
            pool.submit(check_one, node, session, cfg.worker_base, cfg.check_timeout): node
            for node in nodes
        }
        pending = set(futures)
        try:
            for future in as_completed(pending, timeout=max(0.1, deadline - time.monotonic())):
                pending.discard(future)
                results.append(future.result())
        except TimeoutError:
            log("CLOUDFLARE WORKER", f"整体检测超时（{cfg.deadline_s:.0f}s），未完成的节点按失败处理")

    timed_out = 0
    for future in pending:
        node = futures[future]
        if future.done() and not future.cancelled():
            try:
                results.append(future.result())
                continue
            except Exception:  # noqa: BLE001
                pass
        future.cancel()
        stub = node.to_dict()
        stub.update(
            {
                "protocol": "sstp",
                "link": f"sstp://vpn:vpn@{node.host}:{node.port}",
                "status": "failed",
                "success": False,
                "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                "exit": None,
                "latency_ms": None,
                "colo": None,
                "error": "整体检测超时，未完成",
                "worker_error": False,
                "residential": "unknown",
            }
        )
        results.append(stub)
        timed_out += 1
    return results, timed_out


# ---------------------------------------------------------------------------
# 优选入口
# ---------------------------------------------------------------------------
def fetch_optimal_endpoints(cfg: Config, session: requests.Session) -> list[str]:
    raw = (cfg.optimal_api or "").strip()
    if not raw:
        return []
    endpoints: list[str] = []
    seen: set[str] = set()
    for url in (u.strip() for u in raw.split(",") if u.strip()):
        try:
            log("OPTIMAL API", f"请求优选 API: {url}")
            response = session.get(url, timeout=min(cfg.http_timeout, 15))
            if response.status_code != 200:
                log("OPTIMAL API", f"API 返回状态码异常: {response.status_code}")
                continue
            count = 0
            for line in response.text.splitlines():
                endpoint = normalize_endpoint(line)
                if endpoint and endpoint not in seen:
                    seen.add(endpoint)
                    endpoints.append(endpoint)
                    count += 1
            log("OPTIMAL API", f"成功从 API 获取到 {count} 个优选端点")
        except Exception as exc:  # noqa: BLE001
            log("OPTIMAL API", f"拉取优选 API 失败 ({url}): {exc}")
    return endpoints


def get_combined_edge_hosts(cfg: Config, session: requests.Session) -> list[str]:
    api_endpoints = fetch_optimal_endpoints(cfg, session)
    combined: list[str] = []
    seen: set[str] = set()
    for endpoint in list(cfg.edge_hosts) + api_endpoints:
        if endpoint and endpoint not in seen:
            seen.add(endpoint)
            combined.append(endpoint)
    if not combined:
        combined = [h for h in (normalize_endpoint(x) for x in DEFAULT_EDGE_HOSTS) if h]
    log(
        "EDGE POOL",
        f"入口地址池: 静态/配置 {len(cfg.edge_hosts)} 个, API {len(api_endpoints)} 个, 合并 {len(combined)} 个",
    )
    return combined


# ---------------------------------------------------------------------------
# 输出构建与发布（仅发布延迟排名前 N 的节点）
# ---------------------------------------------------------------------------
def atomic_write_text(path: str, content: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    tmp_path = f"{path}.tmp.{os.getpid()}"
    with open(tmp_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    os.replace(tmp_path, path)


def _sanitize_remark_part(text: str) -> str:
    cleaned = re.sub(r"[\r\n|#]+", " ", str(text or "")).strip()
    return re.sub(r"\s+", " ", cleaned)


def build_nodes_text(
    results: Iterable[dict[str, Any]],
    edge_hosts: Iterable[str],
    cfg: Config | None = None,
) -> str:
    """基于延迟排名前 N 的可用节点与入口池生成 nodes.txt 内容。"""
    pool = [ep for ep in (normalize_endpoint(str(h)) for h in edge_hosts) if ep]
    if not pool:
        raise ConfigError("优选入口地址池为空，无法生成 nodes.txt")

    limit = cfg.publish_top_n if cfg is not None else DEFAULT_PUBLISH_TOP_N
    selected = select_top_latency_nodes(results, limit=limit)

    lines: list[str] = []
    seen_lines: set[str] = set()
    for idx, node in enumerate(selected, start=1):
        host = str(node.get("host") or "").strip().lower()
        try:
            port = int(node.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not host or not 1 <= port <= 65535:
            continue

        raw_link = str(node.get("link") or "").strip()
        base_link = raw_link.split("#", 1)[0].strip() if raw_link else f"sstp://vpn:vpn@{host}:{port}"
        if not base_link:
            continue

        code = _sanitize_remark_part(node.get("country_code") or node.get("country") or "UN").upper()
        cc_zh = COUNTRY_ZH.get(code, "")
        latency = node.get("latency_ms")
        lat_str = f"{latency}ms" if latency is not None else ""
        remark_parts = [f"#{idx:02d}", cc_zh or code, f"{host}:{port}", lat_str]
        remark = quote(" | ".join(p for p in remark_parts if p))

        entry = pool[(idx - 1) % len(pool)]
        line = f"{base_link}#{remark}" if "#" not in base_link else base_link
        if entry:
            sep = "&" if "?" in line else "?"
            if "sni=" not in line and "host=" not in line:
                line = f"{line}{sep}edge={quote(entry, safe=':[]')}"

        if line not in seen_lines:
            seen_lines.add(line)
            lines.append(line)

    return ("\n".join(lines) + "\n") if lines else ""


def _group_by_country(nodes: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        code = (
            resolve_country_code(node.get("country_code"), node.get("country"))
            or str(node.get("country_code") or node.get("country") or "UNKNOWN").upper()
        )
        grouped.setdefault(code, []).append(node)
    return grouped


def build_outputs(
    results: Iterable[dict[str, Any]],
    raw_count: int = 0,
    sstp_count: int = 0,
    unique_count: int | None = None,
    source: str = "funcra/vg-mirror/servers_history",
    worker_host: str = "",
    duration_s: float = 0.0,
    timed_out: int = 0,
    edge_hosts: Iterable[str] = (),
    nodes_url: str = "",
    publish_top_n: int = DEFAULT_PUBLISH_TOP_N,
) -> dict[str, Any]:
    """构建发布数据字典（仅保留延迟排名前 publish_top_n 的节点与对应统计）。"""
    all_items = [item for item in results if isinstance(item, dict)]
    checked_count = len(all_items)
    success_count = sum(
        1 for item in all_items if item.get("success") is True or item.get("status") == "success"
    )
    failed_count = max(0, checked_count - success_count)

    published_nodes = select_top_latency_nodes(all_items, limit=publish_top_n)
    countries = _group_by_country(published_nodes)

    latencies = [
        float(n["latency_ms"])
        for n in published_nodes
        if _parse_valid_latency_ms(n.get("latency_ms")) is not None
    ]
    min_latency = _normalize_latency_output(min(latencies)) if latencies else None
    avg_latency = (
        _normalize_latency_output(sum(latencies) / len(latencies)) if latencies else None
    )

    effective_unique = unique_count if unique_count is not None else max(sstp_count, checked_count)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pool_list = [ep for ep in (normalize_endpoint(str(h)) for h in edge_hosts) if ep]

    stats: dict[str, Any] = {
        "raw_nodes": int(raw_count),
        "sstp_nodes": int(sstp_count),
        "unique_nodes": int(effective_unique),
        "checked_nodes": int(checked_count),
        "success": int(success_count),
        "success_count": int(success_count),
        "failed": int(failed_count),
        "failed_count": int(failed_count),
        "timed_out": int(timed_out),
        "published": int(len(published_nodes)),
        "published_count": int(len(published_nodes)),
        "publish_limit": int(publish_top_n),
        "min_latency_ms": min_latency,
        "avg_latency_ms": avg_latency,
        "duration_s": round(float(duration_s), 2),
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at": now_utc,
        "source": source,
        "worker_host": worker_host,
        "nodes_url": nodes_url or derive_nodes_url(),
        "edge_hosts": pool_list,
        "stats": stats,
        "countries": countries,
        "nodes": published_nodes,
    }


def _render_fallback_html(payload: dict[str, Any]) -> str:
    safe_json = json.dumps(payload, ensure_ascii=False, indent=2).replace("</", "<\\/")
    nodes = payload.get("nodes", [])
    title = html.escape(f"SSTP Top {len(nodes)} Nodes")
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; margin: 24px; line-height: 1.5; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 14px; }}
    th {{ background: #f5f5f5; }}
    code {{ word-break: break-all; }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <p>更新时间：<span id="updated-at">{html.escape(str(payload.get("updated_at", "")))}</span> |
     已发布节点数：<span id="published-count">{len(nodes)}</span></p>
  <table>
    <thead>
      <tr><th>#</th><th>延迟 (ms)</th><th>国家/地区</th><th>主机:端口</th><th>链接</th></tr>
    </thead>
    <tbody id="nodes-body"></tbody>
  </table>
  <script id="sstp-data" type="application/json">{safe_json}</script>
  <script>
    const data = JSON.parse(document.getElementById("sstp-data").textContent);
    const tbody = document.getElementById("nodes-body");
    (data.nodes || []).forEach((n, idx) => {{
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${{idx + 1}}</td><td>${{n.latency_ms ?? "-"}}</td><td>${{n.country_code || n.country || "-"}}</td><td>${{n.host}}:${{n.port}}</td><td><code>${{n.link || ""}}</code></td>`;
      tbody.appendChild(tr);
    }});
  </script>
</body>
</html>
"""


def build_html_output(template_path: str, payload: dict[str, Any]) -> str:
    safe_json = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    if template_path and os.path.isfile(template_path):
        with open(template_path, "r", encoding="utf-8") as fh:
            tpl = fh.read()
        if "__SSTP_DATA_JSON__" in tpl:
            return tpl.replace("__SSTP_DATA_JSON__", safe_json)
        if "</body>" in tpl:
            injection = f'\n<script id="sstp-data" type="application/json">{safe_json}</script>\n</body>'
            return tpl.replace("</body>", injection, 1)
    return _render_fallback_html(payload)


def publish_outputs(
    cfg: Config,
    payload: dict[str, Any],
    nodes_text: str,
) -> None:
    """将构建好的发布数据写入 public/data.json、public/nodes.txt 与 public/index.html。"""
    os.makedirs(cfg.public_dir, exist_ok=True)
    data_path = os.path.join(cfg.public_dir, "data.json")
    nodes_path = os.path.join(cfg.public_dir, "nodes.txt")
    html_path = os.path.join(cfg.public_dir, "index.html")

    atomic_write_text(data_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    atomic_write_text(nodes_path, nodes_text)
    atomic_write_text(html_path, build_html_output(cfg.template_html, payload))

    published_count = len(payload.get("nodes", []))
    log(
        "PUBLISH",
        f"已发布 {published_count} 个低延迟节点（上限 {cfg.publish_top_n}）至 {cfg.public_dir} "
        f"(data.json / nodes.txt / index.html)",
    )


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main() -> int:
    started_at = time.monotonic()
    try:
        cfg = Config.load()
    except ConfigError as exc:
        die("CONFIG", str(exc))

    session = make_session(pool_size=max(32, cfg.concurrency + 8), retries=2)
    try:
        rows, source_name = fetch_vpngate(cfg, session)
        raw_count = len(rows)
        log("FILTER", f"原始节点数: {raw_count}，排除国家: {sorted(cfg.blocked_countries)}")
        sstp_nodes = to_sstp_nodes(rows, blocked_countries=cfg.blocked_countries)
        sstp_count = len(sstp_nodes)
        unique_nodes = dedupe_nodes(sstp_nodes)
        unique_count = len(unique_nodes)
        ordered_nodes = prioritize(unique_nodes)

        if cfg.max_check_nodes > 0:
            nodes_to_check = ordered_nodes[: cfg.max_check_nodes]
        else:
            nodes_to_check = ordered_nodes

        log(
            "FILTER",
            f"有效 SSTP 节点: {sstp_count}，去重后: {unique_count}，本次待检测: {len(nodes_to_check)}",
        )

        if not nodes_to_check:
            die("CHECK", "没有可检测的 SSTP 节点")

        log("CLOUDFLARE WORKER", f"并发检测中（并发数: {cfg.concurrency}，单节点超时: {cfg.check_timeout}s）")
        raw_results, timed_out = check_all(nodes_to_check, session, cfg)

        success_count = sum(
            1
            for item in raw_results
            if isinstance(item, dict) and (item.get("success") is True or item.get("status") == "success")
        )
        if success_count == 0:
            die("PUBLISH", "全部节点检测失败（可用节点数为 0），拒绝发布")

        if cfg.min_success_ratio > 0 and nodes_to_check:
            ratio = success_count / len(nodes_to_check)
            if ratio < cfg.min_success_ratio:
                die(
                    "PUBLISH",
                    f"检测成功率 {ratio:.2%} 低于阈值 {cfg.min_success_ratio:.2%}，拒绝发布",
                )

        published_nodes = select_top_latency_nodes(raw_results, limit=cfg.publish_top_n)
        if not published_nodes:
            die("PUBLISH", "没有延迟有效的成功节点可供发布，拒绝发布")

        edge_hosts = get_combined_edge_hosts(cfg, session)
        try:
            nodes_text = build_nodes_text(published_nodes, edge_hosts, cfg)
        except ConfigError as exc:
            die("PUBLISH", str(exc))

        duration_s = time.monotonic() - started_at
        worker_host = urlsplit(cfg.worker_base).netloc
        payload = build_outputs(
            results=published_nodes,
            raw_count=raw_count,
            sstp_count=sstp_count,
            unique_count=unique_count,
            source=source_name,
            worker_host=worker_host,
            duration_s=duration_s,
            timed_out=timed_out,
            edge_hosts=edge_hosts,
            nodes_url=cfg.nodes_url,
            publish_top_n=cfg.publish_top_n,
        )
        publish_outputs(cfg=cfg, payload=payload, nodes_text=nodes_text)
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
