import base64
import csv
import io
import json
import os
import re
import socket
import subprocess
import threading
import time
import logging
import requests
import ipaddress
from collections import OrderedDict
from socks_server import Socks5Server
from datetime import datetime, timezone, timedelta
import uuid

logger = logging.getLogger("vpn_manager")

# ---------- 常量限制 ----------
MAX_HISTORY_RECORDS = 500       # 连接历史最大条数，防止磁盘/内存无限增长
MAX_FAILED_IPS = 1000           # 失败 IP 黑名单最大条数，防止 set 无限膨胀
MAX_CONNECT_ATTEMPTS = 50       # 单次 auto_connect_next 最多尝试的节点数，防止风暴循环
NODE_CONFIG_CACHE_MAX = 200     # 节点配置缓存最大条数（仅缓存最近使用过的）


class VpnManager:
    def __init__(self):
        self.config = self._load_config_safe()
        self.nodes = []
        self.current_node = None
        self.vpn_process = None
        self.socks_server = None
        self.status = {
            "connected": False,
            "node_info": {},
            "ip_info": None,
            "socks": "",
            "connected_since": None
        }
        self._stop_event = threading.Event()
        self._health_thread = None
        self._bg_check_thread = None
        self._auto_update_thread = None
        self._auto_update_trigger = threading.Event()
        self._log_callback = None
        self.tun_dev = None
        self.tun_ip = None
        self.vpn_gateway = None
        self.health_fail_count = 0
        self.max_health_fails = self.config.get("health_fail_threshold", 3)
        self.health_check_interval = self.config.get("health_check_interval", 10)
        self._available_nodes = []
        self._ip_pool = []              # 探测通过的可用 IP 池（不含完整 ovpn 大字段也可，但保留 config 便于切换）
        self._geo_cache = {}            # ip -> (ts, geo dict)
        self._fraud_cache = {}          # ip -> (ts, score)
        self._pool_lock = threading.Lock()
        self._pool_updated_at = None
        self._pool_refreshing = False
        self._rotate_lock = threading.Lock()
        self.policy_routing_set = False
        self._failed_ips = set()
        self.preferred_nodes = self.config.get("preferred_nodes", [])
        self.history_file = "/data/connection_history.json"
        self.connection_history = self._load_history()
        self._history_clean_thread = None
        self._reconnect_fail_count = 0
        self.reconnect_interval = self.config.get("reconnect_interval", 30)
        # 节点配置缓存：IP → openvpn_config_base64，仅缓存最近使用过的节点
        self._node_config_cache = OrderedDict()
        # 线程安全锁
        self._state_lock = threading.Lock()
        # 线程启动标志，防止重复创建线程
        self._threads_started = False

    @staticmethod
    def _load_config_safe():
        import config as cfg_module
        return cfg_module.load_config()

    def set_log_callback(self, cb):
        self._log_callback = cb

    def log(self, message):
        logger.info(message)
        if self._log_callback:
            self._log_callback(message)

    def set_config(self, cfg):
        import config as cfg_module
        if "preferred_nodes" not in cfg:
            cfg["preferred_nodes"] = self.config.get("preferred_nodes", [])
        self.config = cfg
        cfg_module.save_config(cfg)
        self.max_health_fails = self.config.get("health_fail_threshold", 3)
        self.health_check_interval = self.config.get("health_check_interval", 10)
        self.reconnect_interval = self.config.get("reconnect_interval", 30)
        self.preferred_nodes = self.config.get("preferred_nodes", [])
        self._auto_update_trigger.set()

    def fetch_nodes(self):
        self.log("正在获取节点列表...")
        try:
            api_url = self.config.get("api_url", "")
            if not api_url:
                self.log("API 地址未配置，跳过获取节点")
                return
            resp = requests.get(api_url, timeout=30)
            resp.encoding = "utf-8"
            text = resp.text
            lines = text.splitlines()

            header_index = None
            for i, line in enumerate(lines):
                if line.strip().startswith("#HostName"):
                    header_index = i
                    break

            if header_index is None:
                self.log("未找到节点表头，可能 API 格式变化")
                return

            csv_lines = [lines[header_index]]
            for line in lines[header_index+1:]:
                if line.strip() == "":
                    continue
                csv_lines.append(line)

            csv_text = "\n".join(csv_lines)
            reader = csv.DictReader(io.StringIO(csv_text))
            nodes = []
            for row in reader:
                if not row.get("#HostName"):
                    continue
                nodes.append({
                    "hostname": row.get("#HostName", ""),
                    "ip": row.get("IP", ""),
                    "score": row.get("Score", ""),
                    "ping": row.get("Ping", ""),
                    "speed": row.get("Speed", ""),
                    "country_long": row.get("CountryLong", ""),
                    "country_short": row.get("CountryShort", ""),
                    "num_sessions": row.get("NumVpnSessions", ""),
                    "uptime": row.get("Uptime", ""),
                    "total_users": row.get("TotalUsers", ""),
                    "total_traffic": row.get("TotalTraffic", ""),
                    "log_type": row.get("LogType", ""),
                    "operator": row.get("Operator", ""),
                    "message": row.get("Message", ""),
                    "openvpn_config_base64": row.get("OpenVPN_ConfigData_Base64", "")
                })
            self.nodes = nodes
            self.log(f"获取到 {len(nodes)} 个节点")
        except Exception as e:
            self.log(f"获取节点列表失败: {str(e)}")

    @staticmethod
    def _to_int(value, default=0):
        try:
            if value is None or value == "":
                return default
            return int(float(str(value).strip()))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _to_float(value, default=0.0):
        try:
            if value is None or value == "":
                return default
            return float(str(value).strip())
        except (TypeError, ValueError):
            return default

    def _has_openvpn_config(self, node):
        if node.get("openvpn_config_base64"):
            return True
        ip = node.get("ip")
        return bool(ip and ip in self._node_config_cache)

    def _is_viable_node(self, node):
        """过滤明显不可用的低质量节点，尽量靠近优质住宅线水准。"""
        ip = (node.get("ip") or "").strip()
        if not ip:
            return False
        if not self._has_openvpn_config(node):
            return False
        score = self._to_int(node.get("score"))
        speed = self._to_int(node.get("speed"))
        ping = self._to_int(node.get("ping"), default=-1)
        sessions = self._to_int(node.get("num_sessions"))
        min_score = self._to_int(self.config.get("min_node_score"), 0)
        min_speed = self._to_int(self.config.get("min_node_speed"), 0)
        max_ping = self._to_int(self.config.get("max_node_ping"), 0)
        max_sessions = self._to_int(self.config.get("max_node_sessions"), 0)
        if min_score and score < min_score:
            return False
        if min_speed and speed < min_speed:
            return False
        if max_ping > 0 and ping >= 0 and ping > max_ping:
            return False
        if max_sessions > 0 and sessions > max_sessions:
            return False
        # 无有效分数且无有效速率时视为劣质节点
        if score <= 0 and speed <= 0:
            return False
        return True

    def _node_quality_tuple(self, node):
        """
        质量排序键（越大越好）。
        参考优质节点特征（如 121.109.224.163：高分、可用速率、低负载）：
        Score / Speed 为主，Ping 与会话数为辅，国家加权可选。
        """
        score = self._to_float(node.get("score"))
        speed = self._to_float(node.get("speed"))
        ping = self._to_float(node.get("ping"), default=-1.0)
        sessions = self._to_float(node.get("num_sessions"))
        uptime = self._to_float(node.get("uptime"))

        # ping<=0 在 VPNGate 常表示未知；给中性惩罚而不是当成最优
        if ping < 0:
            ping_score = 50.0
        else:
            ping_score = max(0.0, 300.0 - ping)

        # 会话过多通常更卡
        session_score = max(0.0, 100.0 - sessions)

        country = (node.get("country_short") or "").upper()
        boost_countries = self.config.get("quality_boost_countries") or ["JP"]
        if isinstance(boost_countries, str):
            boost_countries = [c.strip().upper() for c in boost_countries.split(",") if c.strip()]
        else:
            boost_countries = [str(c).strip().upper() for c in boost_countries if str(c).strip()]
        country_boost = 1.0 if country in boost_countries else 0.0

        # 归一化组合：Score/Speed 权重最高（与 VPNGate 官网排序一致）
        quality = (
            score * 1.0
            + (speed / 1_000_000.0) * 0.35   # Mbps 量级加权
            + ping_score * 800.0
            + session_score * 500.0
            + (uptime / 86_400_000.0) * 200.0  # 约按天
            + country_boost * 50_000.0
        )
        # 返回 tuple 供稳定排序：quality desc, score desc, speed desc, ping asc, sessions asc
        ping_for_sort = ping if ping >= 0 else 99999.0
        return (quality, score, speed, -ping_for_sort, -sessions, uptime)

    def rank_nodes(self, nodes):
        """按质量降序排列；默认开启，可用 prefer_quality_sort=false 关闭。"""
        if not self.config.get("prefer_quality_sort", True):
            return list(nodes)
        return sorted(nodes, key=self._node_quality_tuple, reverse=True)

    def filter_nodes(self, region="all", *, viable_only=False, ranked=True):
        nodes = list(self.nodes)
        if region != "all":
            nodes = [n for n in nodes if (n.get("country_short") or "").upper() == region.upper()]
        if viable_only or self.config.get("filter_low_quality", True):
            nodes = [n for n in nodes if self._is_viable_node(n)]
        if ranked:
            nodes = self.rank_nodes(nodes)
        return nodes

    def detect_ip(self, ip):
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,isp,proxy,hosting,mobile,query"
            resp = requests.get(url, timeout=10)
            data = resp.json()
            if data.get("status") != "success":
                self.log(f"ip-api 查询失败: {data.get('message')}")
                return None
            return {
                "查询IP": data.get("query", ip),
                "国家": data.get("country", ""),
                "地区": data.get("regionName", ""),
                "城市": data.get("city", ""),
                "ISP": data.get("isp", ""),
                "代理/VPN": "是" if data.get("proxy") else "否",
                "机房/托管": "是" if data.get("hosting") else "否",
                "移动网络": "是" if data.get("mobile") else "否",
            }
        except Exception as e:
            self.log(f"IP检测失败: {str(e)}")
            return None

    @staticmethod
    def _residential_score(geo):
        """家宽启发式：日本常见宽带运营商加分，机房/云厂商减分。"""
        blob = " ".join([
            str(geo.get("isp") or ""),
            str(geo.get("org") or ""),
            str(geo.get("as") or ""),
        ]).lower()
        residential = (
            "kddi", "ntt", "softbank", "ocn", "so-net", "sonet", "biglobe",
            "j:com", "jcom", "plala", "asahi", "nifty", "yahoo", "commufa",
            "iij", "bbix", "eonet", "opticom", "k-opticom", "dti", "hi-ho",
            "wakwak", "gmobb", "au one", "au hikari", "flets", "フレッツ",
            "光", "fiber", "broadband", "vectant", "ucom", "itscom", "pikara",
            # 韩国/台港澳新马泰等常见家宽
            "kt", "korea telecom", "sk broadband", "sk telecom", "lg u+", "lg uplus",
            "lgtelecom", "xpeed", "dacom", "hanaro",
            "chunghwa", "hinet", "fetnet", "taiwan mobile", "kbro",
            "pccw", "hkt", "hkbn", "i-cable", "smartone",
            "singtel", "starhub", "m1 limited",
            "true online", "ais", "tot public", "3bb",
            "tm net", "maxis", "time dotcom",
            "viettel", "vnpt", "fpt",
            "pldt", "globe telecom", "converge",
            "telkom", "indihome", "biznet",
        )
        datacenter = (
            "amazon", "aws", "google", "microsoft", "azure", "digitalocean",
            "linode", "ovh", "hetzner", "alibaba", "tencent", "oracle",
            "choopa", "vultr", "contabo", "leaseweb", "m247", "datacamp",
            "hosting", "datacenter", "data center", "colocation", "cloud",
            "vps", "softlayer", "akamai", "cdn", "university", "academic",
            "opengw", "softether", "server", "dedicated", "colo",
        )
        score = 0
        if any(k in blob for k in residential):
            score += 3
        if any(k in blob for k in datacenter):
            score -= 4
        if score == 0 and not geo.get("hosting") and not geo.get("mobile"):
            score = 1
        return score

    def _allowed_countries(self):
        """支持 pool_country=JP / 'JP,KR' / ['JP','KR']；空或 ALL 表示不限。"""
        raw = self.config.get("pool_country")
        if raw is None or raw == "" or str(raw).upper() == "ALL":
            return None
        if isinstance(raw, (list, tuple, set)):
            items = [str(x).strip().upper() for x in raw if str(x).strip()]
        else:
            items = [x.strip().upper() for x in str(raw).replace(";", ",").split(",") if x.strip()]
        return set(items) or None

    def _lookup_fraud_score(self, ip):
        """查询欺诈分（0-100，越低越干净）。未配置 provider/key 时返回 None。"""
        provider = (self.config.get("fraud_provider") or "none").strip().lower()
        key = (self.config.get("fraud_api_key") or "").strip()
        if provider in ("", "none") or not key:
            return None
        now = time.time()
        ttl = int(self.config.get("fraud_cache_ttl", 86400))
        cached = self._fraud_cache.get(ip)
        if cached and now - cached[0] < ttl:
            return cached[1]
        score = None
        try:
            if provider == "ipqs":
                url = f"https://ipqualityscore.com/api/json/ip/{key}/{ip}"
                params = {
                    "strictness": 1,
                    "allow_public_access_points": "true",
                    "lighter_penalties": "true",
                }
                resp = requests.get(url, params=params, timeout=12)
                data = resp.json() if resp.ok else {}
                if data.get("success") is False:
                    self.log(f"IPQS 查询失败 {ip}: {data.get('message')}")
                else:
                    score = data.get("fraud_score")
            elif provider == "proxycheck":
                url = f"https://proxycheck.io/v2/{ip}"
                params = {"key": key, "vpn": 1, "risk": 1, "asn": 1}
                resp = requests.get(url, params=params, timeout=12)
                data = resp.json() if resp.ok else {}
                row = data.get(ip) if isinstance(data, dict) else None
                if isinstance(row, dict):
                    score = row.get("risk")
            else:
                self.log(f"未知 fraud_provider: {provider}")
                return None
            if score is not None:
                score = int(float(score))
                self._fraud_cache[ip] = (now, score)
        except Exception as e:
            self.log(f"欺诈分查询失败 {ip}: {e}")
            return None
        return score

    def _geo_passes(self, geo, fraud_score=None):
        if not geo or geo.get("status") != "success":
            return False
        allowed = self._allowed_countries()
        if allowed is not None:
            cc = (geo.get("countryCode") or "").upper()
            if cc not in allowed:
                return False
        if self.config.get("pool_reject_proxy", False) and geo.get("proxy"):
            return False
        if self.config.get("pool_reject_hosting", True) and geo.get("hosting"):
            return False
        if self.config.get("pool_reject_mobile", True) and geo.get("mobile"):
            return False
        res = self._residential_score(geo)
        if self.config.get("pool_require_residential", True) and res <= 0:
            return False
        if (
            fraud_score is not None
            and self.config.get("fraud_hard_filter", True)
            and fraud_score > int(self.config.get("max_fraud_score", 40))
        ):
            return False
        return True

    def _lookup_geo_batch(self, ips):
        """批量查 ip-api，带缓存。返回 {ip: geo}。"""
        now = time.time()
        ttl = int(self.config.get("pool_geo_cache_ttl", 21600))
        out = {}
        missing = []
        for ip in ips:
            if not ip:
                continue
            cached = self._geo_cache.get(ip)
            if cached and now - cached[0] < ttl:
                out[ip] = cached[1]
            else:
                missing.append(ip)
        if not missing:
            return out

        url = (
            "http://ip-api.com/batch"
            "?fields=status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query"
        )
        for i in range(0, len(missing), 100):
            chunk = missing[i:i + 100]
            try:
                resp = requests.post(url, json=chunk, timeout=20)
                if resp.status_code == 429:
                    self.log("ip-api 频率限制，稍后重试剩余 IP")
                    time.sleep(2)
                    resp = requests.post(url, json=chunk, timeout=20)
                rows = resp.json() if resp.ok else []
                if not isinstance(rows, list):
                    self.log(f"ip-api 批量查询异常: {resp.status_code}")
                    continue
                for row in rows:
                    ip = (row or {}).get("query")
                    if not ip:
                        continue
                    self._geo_cache[ip] = (now, row)
                    out[ip] = row
            except Exception as e:
                self.log(f"ip-api 批量查询失败: {e}")
        return out

    def _attach_geo(self, item, geo):
        item = dict(item)
        item["geo_country"] = geo.get("countryCode") or ""
        item["city"] = geo.get("city") or ""
        item["isp"] = geo.get("isp") or ""
        item["org"] = geo.get("org") or ""
        item["proxy"] = bool(geo.get("proxy"))
        item["hosting"] = bool(geo.get("hosting"))
        item["mobile"] = bool(geo.get("mobile"))
        item["residential_score"] = self._residential_score(geo)
        item["residential"] = item["residential_score"] > 0 and not item["hosting"]
        return item

    def _extract_ovpn_remotes(self, node):
        """从 OpenVPN 配置解析 remote 列表: [(host, port, proto), ...]"""
        config_b64 = self._get_node_config(node)
        if not config_b64:
            return []
        try:
            content = base64.b64decode(config_b64).decode("utf-8", errors="ignore")
        except Exception:
            return []
        remotes = []
        default_proto = "udp"
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            lower = line.lower()
            if lower.startswith("proto "):
                parts = line.split()
                if len(parts) >= 2:
                    default_proto = parts[1].split("-")[0].lower()
                continue
            if lower.startswith("remote "):
                parts = line.split()
                if len(parts) < 2:
                    continue
                host = parts[1]
                port = 1194
                proto = default_proto
                if len(parts) >= 3 and parts[2].isdigit():
                    port = int(parts[2])
                if len(parts) >= 4:
                    proto = parts[3].split("-")[0].lower()
                remotes.append((host, port, proto))
        return remotes

    def test_node(self, node):
        """连接前轻量探测：缺配置直接失败；TCP 端口可连则通过；纯 UDP 仅检查配置完整。"""
        if not self._is_viable_node(node):
            return False
        remotes = self._extract_ovpn_remotes(node)
        if not remotes:
            # 无 remote 行时仍允许尝试（部分配置用 <connection> 块），交给 OpenVPN
            return self._has_openvpn_config(node)
        # 任一 TCP remote 可达即视为优质可用；全是 UDP 则不做误杀式探测
        tcp_remotes = [(h, p) for h, p, proto in remotes if proto == "tcp"]
        if not tcp_remotes:
            return True
        timeout = float(self.config.get("node_probe_timeout", 2.5))
        for host, port in tcp_remotes[:3]:
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    return True
            except OSError:
                continue
        return False

    def _get_tun_info(self):
        try:
            result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True)
            matches = re.findall(r"(tun\d+):\s.*?\n\s+inet (\d+\.\d+\.\d+\.\d+)", result.stdout, re.DOTALL)
            if matches:
                dev, ip = matches[-1]
                return ip, dev
        except Exception:
            pass
        return None, None

    def _setup_policy_routing(self, ip, dev):
        try:
            subprocess.run(["ip", "rule", "add", "from", ip, "table", "100"], check=False)
            if self.vpn_gateway:
                subprocess.run(
                    ["ip", "route", "add", "default", "via", self.vpn_gateway, "dev", dev, "table", "100"],
                    check=False
                )
                self.log(f"策略路由已配置: from {ip} table 100 (default via {self.vpn_gateway} dev {dev})")
            else:
                subprocess.run(
                    ["ip", "route", "add", "default", "dev", dev, "table", "100"],
                    check=False
                )
                self.log(f"策略路由已配置: from {ip} table 100 (default dev {dev})")
            self.policy_routing_set = True
        except Exception as e:
            self.log(f"配置策略路由失败: {e}")

    def _teardown_policy_routing(self, ip, dev):
        if not self.policy_routing_set:
            return
        try:
            subprocess.run(["ip", "rule", "del", "from", ip, "table", "100"], check=False)
            if self.vpn_gateway:
                subprocess.run(
                    ["ip", "route", "del", "default", "via", self.vpn_gateway, "dev", dev, "table", "100"],
                    check=False
                )
            else:
                subprocess.run(
                    ["ip", "route", "del", "default", "dev", dev, "table", "100"],
                    check=False
                )
            self.log("策略路由已清理")
        except Exception as e:
            self.log(f"清理策略路由失败: {e}")

    def _get_node_config(self, node):
        """获取节点的 OpenVPN 配置 base64，优先从内存中的节点数据获取，其次从缓存获取"""
        config_b64 = node.get("openvpn_config_base64")
        if config_b64:
            return config_b64
        # 从缓存中查找
        ip = node.get("ip")
        if ip and ip in self._node_config_cache:
            return self._node_config_cache[ip]
        return None

    def _cache_node_config(self, node):
        """将节点的 OpenVPN 配置缓存起来，供后续重连使用"""
        ip = node.get("ip")
        config_b64 = node.get("openvpn_config_base64")
        if ip and config_b64:
            if ip in self._node_config_cache:
                # 已存在则移到末尾（最近使用）
                self._node_config_cache.move_to_end(ip)
            else:
                # 限制缓存大小，防止内存无限增长
                if len(self._node_config_cache) >= NODE_CONFIG_CACHE_MAX:
                    self._node_config_cache.popitem(last=False)  # 移除最早的
                self._node_config_cache[ip] = config_b64

    def connect_node(self, node):
        self.disconnect()
        time.sleep(0.5)
        self.current_node = node
        hostname = node.get("hostname", "未知")
        ip = node.get("ip", "")
        if not ip:
            self.log("节点数据异常：缺少 IP 地址")
            return False
        self.log(f"正在连接到节点: {hostname} ({ip})")

        # 获取 OpenVPN 配置
        config_b64 = self._get_node_config(node)
        if not config_b64:
            self.log("未找到节点 OpenVPN 配置，无法连接")
            self._mark_node_bad(ip, "missing ovpn")
            return False

        # 缓存配置供后续重连使用
        self._cache_node_config({"ip": ip, "openvpn_config_base64": config_b64})

        try:
            ovpn_content = base64.b64decode(config_b64).decode("utf-8")
        except Exception:
            self.log("解码 OpenVPN 配置失败")
            self._mark_node_bad(ip, "bad ovpn")
            return False

        auth_path = "/tmp/vpn_auth.txt"
        with open(auth_path, "w") as f:
            f.write(f"{self.config.get('vpn_user', '')}\n{self.config.get('vpn_pass', '')}\n")

        if "auth-user-pass" not in ovpn_content:
            ovpn_content += f"\nauth-user-pass {auth_path}\n"

        ovpn_content += "\nroute-nopull\n"
        ovpn_content += "\ndata-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC:CHACHA20-POLY1305\n"
        # 失败节点别长时间重试，尽快换池里下一个
        ovpn_content += "\nconnect-retry-max 1\n"
        ovpn_content += "\nconnect-retry 1\n"
        ovpn_content += "\nresolv-retry 3\n"

        ovpn_path = "/tmp/vpn_config.ovpn"
        with open(ovpn_path, "w") as f:
            f.write(ovpn_content)

        try:
            self.vpn_process = subprocess.Popen(
                ["openvpn", "--config", ovpn_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
        except Exception as e:
            self.log(f"启动 OpenVPN 失败: {str(e)}")
            self._mark_node_bad(ip, "start failed")
            return False

        tun_ip = None
        tun_dev = None
        vpn_gateway = None
        connected_flag = False
        start_time = time.time()
        timeout = int(self.config.get("openvpn_connect_timeout", 18))

        while time.time() - start_time < timeout:
            if self.vpn_process.poll() is not None:
                self.log("OpenVPN 进程已退出，连接失败")
                self._mark_node_bad(ip, "openvpn exited")
                self._cleanup_vpn_process()
                return False

            line = self.vpn_process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue

            self.log(f"[OpenVPN] {line.strip()}")
            low = line.lower()

            # 连接重置 / 认证失败：立刻放弃，别等 Restart pause
            if (
                "connection reset" in low
                or "auth_failed" in low
                or "auth-failure" in low
                or "tls handshake failed" in low
                or "tls error" in low
                or "fatal error" in low
            ):
                self.log(f"OpenVPN 快速失败: {line.strip()}")
                self._mark_node_bad(ip, "openvpn fast-fail")
                self.disconnect()
                return False

            if "Peer Connection Initiated" in line:
                self.log("TLS 握手成功，等待配置...")

            if "PUSH: Received control message: 'PUSH_REPLY" in line:
                match = re.search(r"ifconfig (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    vpn_gateway = match.group(2)
                    self.log(f"提取到 VPN 网关 IP: {vpn_gateway}")

            if "Initialization Sequence Completed" in line:
                connected_flag = True
                self.log("OpenVPN 初始化完成")
                break

            if "net_addr_ptp_v4_add" in line:
                match = re.search(r"net_addr_ptp_v4_add: (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    tun_ip = match.group(1)
                    self.log(f"从 OpenVPN 日志获取到 VPN IP: {tun_ip}")

        if connected_flag or tun_ip:
            self.log("正在从系统获取 VPN 接口信息...")
            sys_ip, sys_dev = self._get_tun_info()
            if sys_ip:
                tun_ip = sys_ip
                tun_dev = sys_dev
            else:
                self.log("无法从系统获取 VPN IP")
                self._mark_node_bad(ip, "no tun ip")
                self.disconnect()
                return False
        else:
            self.log("获取 VPN IP 失败，无法启动 SOCKS5 代理")
            self._mark_node_bad(ip, "connect timeout")
            self.disconnect()
            return False

        self.tun_dev = tun_dev
        self.tun_ip = tun_ip
        self.vpn_gateway = vpn_gateway
        self.health_fail_count = 0

        self._setup_policy_routing(tun_ip, tun_dev)
        time.sleep(1)
        self.log(f"VPN 连接成功，本机 VPN IP: {tun_ip}, 接口: {tun_dev}, 网关: {vpn_gateway}")

        socks_bind = "0.0.0.0"
        socks_port = self.config.get("socks_port", 1080)
        max_conn = self.config.get("socks_max_connections", 200)
        self.socks_server = Socks5Server(socks_bind, socks_port, tun_ip, max_connections=max_conn)
        self.socks_server.start()

        # 隧道预热：通过 SOCKS5 发一个测试请求，激活 VPN 隧道的 TLS 会话和路由
        # 防止浏览器第一个 HTTPS 请求因隧道未完全就绪而失败（ERR_CONNECTION_CLOSED）
        self._warmup_tunnel(socks_port)

        self.status["connected"] = True
        self.status["node_info"] = node
        self.status["socks"] = f"socks5://{self._get_host_ip()}:{socks_port}"
        self.status["ip_info"] = self.detect_ip(ip)
        self.log(f"SOCKS5 代理已启动: {self.status['socks']}")

        # 连上后再核一次出口画像：日本 / 非VPN / 非机房
        if self.config.get("pool_verify_exit_geo", True):
            geos = self._lookup_geo_batch([ip])
            geo = geos.get(ip) or {}
            use_fraud = (
                (self.config.get("fraud_provider") or "none").lower() not in ("", "none")
                and bool((self.config.get("fraud_api_key") or "").strip())
            )
            fraud_score = self._lookup_fraud_score(ip) if use_fraud else None
            if not self._geo_passes(geo, fraud_score=fraud_score):
                self.log(f"出口画像不合格，断开并剔除: {ip} geo={geo} fraud={fraud_score}")
                self._mark_node_bad(ip, "exit geo/fraud rejected")
                self.disconnect()
                return False

        self.status["connected_since"] = datetime.now(timezone.utc).isoformat()
        self.log(f"已记录连接开始时间: {self.status['connected_since']}")
        self.add_connection_record(node)
        self._failed_ips.clear()                      # 连接成功清空整个黑名单，让优先节点下次可用
        self._reconnect_fail_count = 0
        return True

    def _cleanup_vpn_process(self):
        """安全清理 OpenVPN 进程，防止僵尸/孤儿进程"""
        proc = self.vpn_process
        self.vpn_process = None
        if proc is None:
            return
        try:
            proc.terminate()
            try:
                proc.stdout.close()
            except Exception:
                pass
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                try:
                    proc.stdout.close()
                except Exception:
                    pass
                proc.wait(timeout=3)
            except Exception:
                pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def disconnect(self):
        if self.status.get("connected_since") and self.status.get("node_info"):
            try:
                start = datetime.fromisoformat(self.status["connected_since"])
                duration = datetime.now(timezone.utc) - start
                duration_str = str(duration).split('.')[0]
                hostname = self.status["node_info"].get("hostname", "")
                ip = self.status["node_info"].get("ip", "")
                self.log(f"节点 {hostname} ({ip}) 已断开，使用时长: {duration_str}")
            except Exception as e:
                self.log(f"记录使用时长异常: {e}")
        self.status["connected_since"] = None

        if self.status.get("node_info") and self.status["node_info"].get("ip"):
            self.update_connection_record_end(self.status["node_info"]["ip"])

        if self.tun_ip and self.tun_dev:
            self._teardown_policy_routing(self.tun_ip, self.tun_dev)

        self._cleanup_vpn_process()

        if self.socks_server:
            self.socks_server.stop()
            self.socks_server = None
        self.tun_dev = None
        self.tun_ip = None
        self.vpn_gateway = None
        self.status["connected"] = False
        self.status["node_info"] = {}
        self.status["socks"] = ""
        self.policy_routing_set = False

    def _warmup_tunnel(self, socks_port):
        """隧道预热：通过 SOCKS5 发一个轻量请求，激活 VPN 隧道的 TLS 会话和路由缓存。
        防止浏览器第一个 HTTPS 请求因隧道未完全就绪而失败。"""
        try:
            self.log("正在预热 VPN 隧道...")
            result = subprocess.run(
                ["curl", "-s", "--socks5", f"127.0.0.1:{socks_port}",
                 "--max-time", "10", "--connect-timeout", "5",
                 "-o", "/dev/null", "-w", "%{http_code}",
                 "http://httpbin.org/ip"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                self.log(f"隧道预热成功 (HTTP {result.stdout.strip()})")
            else:
                # 预热失败不影响连接状态，只是警告
                self.log(f"隧道预热未成功: {result.stderr.strip() or '无响应'}")
        except Exception as e:
            self.log(f"隧道预热异常（不影响连接）: {e}")

    def _get_host_ip(self):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            return ip
        except Exception:
            return "127.0.0.1"
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

    def _load_history(self):
        if not os.path.exists(self.history_file):
            return []
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save_history(self):
        try:
            # 原子写入历史文件，防止写入中途崩溃导致数据损坏
            import tempfile
            dir_name = os.path.dirname(self.history_file) or "."
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self.connection_history, f, indent=2, ensure_ascii=False)
                os.replace(tmp_path, self.history_file)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except Exception as e:
            self.log(f"保存连接历史失败: {e}")

    def add_connection_record(self, node_info):
        record = {
            "id": str(uuid.uuid4())[:8],
            "hostname": node_info.get("hostname", ""),
            "ip": node_info.get("ip", ""),
            "country": node_info.get("country_long", ""),
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": None,
            "duration": None
        }
        with self._state_lock:
            self.connection_history.insert(0, record)
            # 限制历史记录数量，防止磁盘/内存无限增长
            if len(self.connection_history) > MAX_HISTORY_RECORDS:
                self.connection_history = self.connection_history[:MAX_HISTORY_RECORDS]
            self._save_history()

    def update_connection_record_end(self, node_ip, end_time=None):
        if not end_time:
            end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._state_lock:
            for rec in self.connection_history:
                if rec.get("ip") == node_ip and rec.get("end_time") is None:
                    rec["end_time"] = end_time
                    try:
                        start = datetime.strptime(rec["start_time"], "%Y-%m-%d %H:%M:%S")
                        duration = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S") - start
                        rec["duration"] = str(duration).split('.')[0]
                    except Exception:
                        rec["duration"] = None
                    self._save_history()
                    return

    def delete_connection_record(self, record_id):
        with self._state_lock:
            self.connection_history = [r for r in self.connection_history if r["id"] != record_id]
            self._save_history()

    def clean_old_history(self):
        retention_days = self.config.get("connection_history_retention_days", 30)
        cutoff = datetime.now() - timedelta(days=retention_days)
        with self._state_lock:
            before_count = len(self.connection_history)
            cleaned = []
            for r in self.connection_history:
                try:
                    start_str = r.get("start_time")
                    if not start_str:
                        continue  # 无时间戳的脏数据直接丢弃
                    if datetime.strptime(start_str, "%Y-%m-%d %H:%M:%S") > cutoff:
                        cleaned.append(r)
                except (ValueError, TypeError):
                    continue  # 时间格式异常的脏数据直接丢弃
            self.connection_history = cleaned
            after_count = len(self.connection_history)
            if before_count != after_count:
                self.log(f"清理过期连接记录: {before_count} → {after_count}")
            self._save_history()

    def _history_clean_loop(self):
        while not self._stop_event.is_set():
            # 每 6 小时清理一次，使用 wait 替代循环 sleep，收到停止信号立即返回
            self._stop_event.wait(21600)
            if self._stop_event.is_set():
                return
            self.clean_old_history()

    def _add_failed_ip(self, ip):
        """添加失败 IP，限制集合大小防止无限增长"""
        if not ip:
            return
        self._failed_ips.add(ip)
        if len(self._failed_ips) > MAX_FAILED_IPS:
            # 超过上限时清空一半（set 无序，无法精确保留"最近的"，但配合定期 clear 不影响功能）
            self._failed_ips.clear()
            self._failed_ips.add(ip)  # 保留当前这个

    def _evict_from_pool(self, ip, reason=""):
        if not ip:
            return
        with self._pool_lock:
            before = len(self._ip_pool)
            self._ip_pool = [n for n in self._ip_pool if n.get("ip") != ip]
            after = len(self._ip_pool)
        if before != after:
            self.log(f"已从 IP 池剔除 {ip}" + (f"（{reason}）" if reason else "") + f"，剩余 {after}")

    def _mark_node_bad(self, ip, reason=""):
        """连接失败：进黑名单并从池中剔除，避免反复白试。"""
        self._add_failed_ip(ip)
        self._evict_from_pool(ip, reason=reason or "connect failed")

    def _is_tunnel_alive(self):
        # ---- 第一层：检查 OpenVPN 进程 ----
        if not self.vpn_process or self.vpn_process.poll() is not None:
            self.log("健康检测失败: OpenVPN 进程未运行")
            return False

        # ---- 第二层：检查 tun 接口和 IP（快速失败，避免无意义的 HTTP 检测） ----
        if not self.tun_dev or not self.tun_ip:
            self.log("健康检测失败: tun 接口未分配 IP")
            return False
        try:
            ip_check = subprocess.run(
                ["ip", "addr", "show", "dev", self.tun_dev],
                capture_output=True, text=True, timeout=5
            )
            if ip_check.returncode != 0:
                self.log(f"健康检测失败: tun 接口 {self.tun_dev} 不存在 (可能 VPN 隧道已断开)")
                return False
            if self.tun_ip not in ip_check.stdout:
                self.log(f"健康检测失败: tun 接口 {self.tun_dev} 上的 IP {self.tun_ip} 已丢失 (VPN 隧道断开)")
                return False
        except Exception as e:
            self.log(f"健康检测失败: 检查 tun 接口异常 - {e}")
            return False

        # ---- 第三层：通过 SOCKS5 代理访问检测 URL ----
        raw_urls = self.config.get("health_check_urls", "")
        if raw_urls.strip():
            urls = [u.strip() for u in re.split(r'[,\n]', raw_urls) if u.strip()]
            urls = [u if u.startswith('http://') or u.startswith('https://') else f'http://{u}' for u in urls]
        else:
            urls = [
                "http://httpbin.org/ip",
                "http://ifconfig.me",
                "http://www.google.com"
            ]

        socks_port = self.config.get("socks_port", 1080)
        timeout = self.config.get("health_check_timeout", 8)
        if not isinstance(timeout, (int, float)) or timeout < 3:
            timeout = 8

        for url in urls:
            try:
                result = subprocess.run(
                    ["curl", "-s", "--socks5", f"127.0.0.1:{socks_port}",
                     "--max-time", str(timeout), "-w", "\n%{http_code}", url],
                    capture_output=True, text=True, timeout=timeout + 3
                )
                output = result.stdout.strip()
                if result.returncode == 0 and output:
                    # 分离 HTTP 状态码和响应体
                    lines = output.rsplit('\n', 1)
                    body = lines[0] if len(lines) > 1 else output
                    http_code = lines[-1] if len(lines) > 1 else ""
                    if body.strip():
                        self.log(f"健康检测成功: {url} 访问正常 (HTTP {http_code})")
                        return True
                    else:
                        self.log(f"健康检测尝试 {url} 失败: 连接成功但无响应数据 (HTTP {http_code})")
                elif result.returncode == 7:
                    # curl exit code 7 = couldn't connect to host
                    self.log(f"健康检测尝试 {url} 失败: SOCKS5 代理连接失败 (隧道可能断开)")
                else:
                    self.log(f"健康检测尝试 {url} 失败: {result.stderr.strip() or f'curl 退出码 {result.returncode}'}")
            except subprocess.TimeoutExpired:
                self.log(f"健康检测尝试 {url} 超时 ({timeout}秒)")
            except Exception as e:
                self.log(f"健康检测尝试 {url} 异常: {e}")

        self.log("健康检测失败: 所有检测地址均无法访问")
        return False

    def measure_latency(self):
        if not self.tun_dev or not self.tun_ip:
            return -1

        target = self.config.get("latency_check_target", "").strip()
        if not target:
            target = self.vpn_gateway if self.vpn_gateway else "8.8.8.8"

        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", "-I", self.tun_dev, target],
                capture_output=True, text=True, timeout=5
            )
            if "time=" in result.stdout:
                match = re.search(r"time=(\d+\.?\d*) ms", result.stdout)
                if match:
                    return round(float(match.group(1)), 1)
            return -1
        except Exception:
            return -1

    # ============ 健康检查循环 ============
    def health_check_loop(self):
        last_reconnect_time = 0
        while not self._stop_event.is_set():
            time.sleep(self.health_check_interval)
            if self._stop_event.is_set():
                break
            if not self.status["connected"]:
                self.health_fail_count = 0
                now = time.time()
                if now - last_reconnect_time > self.reconnect_interval:
                    self.log("检测到未连接，尝试自动重连...")
                    success, msg = self.auto_connect_next()
                    if success:
                        self.log(f"自动重连成功: {msg}")
                        self._reconnect_fail_count = 0
                    else:
                        self.log(f"自动重连失败: {msg}")
                        self._reconnect_fail_count += 1
                        if self._reconnect_fail_count >= 3:
                            self.log("自动重连连续失败3次，清空IP黑名单以便重新尝试所有节点")
                            self._failed_ips.clear()
                            self._reconnect_fail_count = 0
                    last_reconnect_time = now
                continue

            if self._is_tunnel_alive():
                self.health_fail_count = 0
                self._reconnect_fail_count = 0
            else:
                self.health_fail_count += 1
                self.log(f"健康检测失败 (连续 {self.health_fail_count} 次)")

            if self.health_fail_count >= self.max_health_fails:
                self.log(f"连续 {self.health_fail_count} 次健康检测失败，准备切换节点")
                self._switch_to_next_available()
                self.health_fail_count = 0

    def _slim_pool_node(self, node, probed=True):
        return {
            "hostname": node.get("hostname", ""),
            "ip": node.get("ip", ""),
            "score": node.get("score", ""),
            "ping": node.get("ping", ""),
            "speed": node.get("speed", ""),
            "country_long": node.get("country_long", ""),
            "country_short": node.get("country_short", ""),
            "num_sessions": node.get("num_sessions", ""),
            "uptime": node.get("uptime", ""),
            "probed": bool(probed),
            "openvpn_config_base64": node.get("openvpn_config_base64")
                or self._node_config_cache.get(node.get("ip"), ""),
        }

    def get_ip_pool(self):
        with self._pool_lock:
            pool = list(self._ip_pool)
            updated = self._pool_updated_at
        # API 不返回超大 base64，除非明确需要
        public = []
        for n in pool:
            public.append({k: v for k, v in n.items() if k != "openvpn_config_base64"})
        return {
            "count": len(public),
            "updated_at": updated,
            "refreshing": self._pool_refreshing,
            "ips": public,
        }

    def refresh_ip_pool(self, force_fetch=False):
        """拉取/过滤/探测节点，更新实时 IP 池。"""
        if not self.config.get("pool_enabled", True):
            return self.get_ip_pool()
        if self._pool_refreshing and not force_fetch:
            return self.get_ip_pool()
        self._pool_refreshing = True
        try:
            if force_fetch or not self.nodes:
                self.fetch_nodes()
            allowed = self._allowed_countries()
            if allowed is None:
                region = self.config.get("region") or "all"
                candidates = self.filter_nodes(region, viable_only=True, ranked=True)
                region = region if region != "all" else "ALL"
            elif len(allowed) == 1:
                region = next(iter(allowed))
                candidates = self.filter_nodes(region, viable_only=True, ranked=True)
            else:
                # 多国家：先全量 viable，再按国家白名单筛
                region = ",".join(sorted(allowed))
                candidates = [
                    n for n in self.filter_nodes("all", viable_only=True, ranked=False)
                    if (n.get("country_short") or "").upper() in allowed
                ]
                candidates = self.rank_nodes(candidates)
            # pool_probe_limit<=0 表示探测全部候选；>0 只探质量排序后的前 N 个
            raw_limit = int(self.config.get("pool_probe_limit", self.config.get("check_limit", 0)))
            max_size = int(self.config.get("pool_max_size", 100))
            if raw_limit <= 0:
                to_probe = list(candidates)
            else:
                to_probe = candidates[:raw_limit]
            self.log(
                f"IP 池刷新：全表后候选 {len(candidates)} 个"
                f"（地区={region}），本轮探测 {len(to_probe)} 个"
                + ("（全部候选）" if raw_limit <= 0 else f"（上限 pool_probe_limit={raw_limit}）")
            )

            passed = []
            from concurrent.futures import ThreadPoolExecutor, as_completed

            def probe(node):
                if self._stop_event.is_set():
                    return None
                if self.config.get("precheck_nodes", True):
                    ok = self.test_node(node)
                else:
                    ok = self._is_viable_node(node)
                if not ok:
                    return None
                # 缓存 ovpn 配置，换 IP 时用
                self._cache_node_config(node)
                return self._slim_pool_node(node, probed=True)

            workers = min(20, max(4, len(to_probe) or 1))
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = [ex.submit(probe, n) for n in to_probe]
                for fut in as_completed(futs):
                    if self._stop_event.is_set():
                        break
                    try:
                        item = fut.result()
                    except Exception:
                        item = None
                    if item and item.get("ip"):
                        passed.append(item)

            # 去重
            by_ip = {}
            for n in passed:
                by_ip[n["ip"]] = n

            geos = self._lookup_geo_batch(list(by_ip.keys()))
            qualified = []
            dropped = {
                "country": 0, "proxy": 0, "hosting": 0, "mobile": 0,
                "residential": 0, "fraud": 0, "unknown": 0,
            }
            use_fraud = (
                (self.config.get("fraud_provider") or "none").lower() not in ("", "none")
                and bool((self.config.get("fraud_api_key") or "").strip())
            )
            for ip, node in by_ip.items():
                geo = geos.get(ip)
                if not geo:
                    dropped["unknown"] += 1
                    continue
                fraud_score = self._lookup_fraud_score(ip) if use_fraud else None
                if not self._geo_passes(geo, fraud_score=fraud_score):
                    allowed = self._allowed_countries()
                    if allowed is not None and (geo.get("countryCode") or "").upper() not in allowed:
                        dropped["country"] += 1
                    elif geo.get("hosting") and self.config.get("pool_reject_hosting", True):
                        dropped["hosting"] += 1
                    elif geo.get("mobile") and self.config.get("pool_reject_mobile", True):
                        dropped["mobile"] += 1
                    elif self.config.get("pool_reject_proxy", False) and geo.get("proxy"):
                        dropped["proxy"] += 1
                    elif self.config.get("pool_require_residential", True) and self._residential_score(geo) <= 0:
                        dropped["residential"] += 1
                    elif (
                        fraud_score is not None
                        and self.config.get("fraud_hard_filter", True)
                        and fraud_score > int(self.config.get("max_fraud_score", 40))
                    ):
                        dropped["fraud"] += 1
                    else:
                        dropped["unknown"] += 1
                    continue
                item = self._attach_geo(node, geo)
                if fraud_score is not None:
                    item["fraud_score"] = fraud_score
                qualified.append(item)

            if self.config.get("pool_prefer_residential", True):
                qualified.sort(
                    key=lambda n: (
                        n.get("residential_score") or 0,
                        -(n.get("fraud_score") if n.get("fraud_score") is not None else 999),
                        self._node_quality_tuple(n),
                    ),
                    reverse=True,
                )
            else:
                qualified = self.rank_nodes(qualified)
            ranked = qualified[:max_size]
            now = datetime.now(timezone.utc).isoformat()
            with self._pool_lock:
                self._ip_pool = ranked
                self._pool_updated_at = now
                self._available_nodes = ranked
            res_n = sum(1 for n in ranked if n.get("residential"))
            hard = bool(self.config.get("fraud_hard_filter", True))
            self.log(
                f"IP 池已更新：{len(ranked)} 个（家宽 {res_n}，欺诈硬过滤={'开' if hard else '关'}），"
                f"剔除 国家{dropped['country']} 机房{dropped['hosting']} "
                f"移动{dropped['mobile']} 非家宽{dropped['residential']} "
                f"欺诈{dropped['fraud']} 代理{dropped['proxy']} 未知{dropped['unknown']}"
            )
            return self.get_ip_pool()
        finally:
            self._pool_refreshing = False

    def pick_from_pool(self, exclude_ips=None):
        exclude = set(exclude_ips or [])
        with self._pool_lock:
            pool = list(self._ip_pool)
        picks = []
        for n in pool:
            ip = n.get("ip")
            if not ip or ip in exclude or ip in self._failed_ips:
                continue
            # 补全配置
            if not n.get("openvpn_config_base64"):
                n["openvpn_config_base64"] = self._node_config_cache.get(ip, "")
            if not n.get("openvpn_config_base64"):
                # 从全量 nodes 找
                for full in self.nodes:
                    if full.get("ip") == ip and full.get("openvpn_config_base64"):
                        n["openvpn_config_base64"] = full["openvpn_config_base64"]
                        break
            if n.get("openvpn_config_base64"):
                picks.append(n)
        return picks

    def change_ip(self, exclude_current=True):
        """
        从 IP 池选择另一个节点，切换唯一 SOCKS5 出口（单隧道）。
        供外部程序调用。
        """
        if not self._rotate_lock.acquire(blocking=False):
            return False, {"error": "正在切换中，请稍后重试"}
        try:
            last_ip = None
            if exclude_current:
                if self.current_node:
                    last_ip = self.current_node.get("ip")
                elif self.status.get("node_info"):
                    last_ip = self.status["node_info"].get("ip")

            # 池空则先刷新
            with self._pool_lock:
                empty = len(self._ip_pool) == 0
            if empty:
                self.log("IP 池为空，先刷新再换 IP")
                self.refresh_ip_pool(force_fetch=True)

            exclude = {last_ip} if last_ip else set()
            candidates = self.pick_from_pool(exclude_ips=exclude)
            if not candidates:
                # 放宽：清空失败黑名单后再取
                self._failed_ips.clear()
                candidates = self.pick_from_pool(exclude_ips=exclude)
            if not candidates:
                return False, {"error": "IP 池中没有可切换节点", "pool": self.get_ip_pool()}

            for round_i in range(2):
                candidates = self.pick_from_pool(exclude_ips=exclude)
                if not candidates:
                    self._failed_ips -= exclude  # 不清空 exclude，只是别被旧黑名单堵死过多
                    self.log("换 IP：池空，强制刷新")
                    self.refresh_ip_pool(force_fetch=True)
                    candidates = self.pick_from_pool(exclude_ips=exclude)
                if not candidates:
                    break
                max_try = min(MAX_CONNECT_ATTEMPTS, len(candidates))
                self.log(f"收到换 IP 请求，池内候选 {len(candidates)}，最多尝试 {max_try} 个（第 {round_i + 1} 轮）")
                for node in candidates[:max_try]:
                    if self._stop_event.is_set():
                        break
                    ip = node.get("ip")
                    host = node.get("hostname", "未知")
                    self.log(f"换 IP 尝试: {host} ({ip})")
                    if self.connect_node(node):
                        socks = self.status.get("socks", "")
                        info = {
                            "success": True,
                            "ip": ip,
                            "hostname": host,
                            "country": node.get("country_short") or node.get("geo_country", ""),
                            "socks": socks,
                            "connected": True,
                            "score": node.get("score"),
                            "ping": node.get("ping"),
                            "speed": node.get("speed"),
                            "residential": node.get("residential"),
                            "isp": node.get("isp"),
                        }
                        self.log(f"换 IP 成功: {host} ({ip})")
                        return True, info
                if round_i == 0:
                    self.refresh_ip_pool(force_fetch=True)
            return False, {"error": "尝试池内节点均失败", "pool": self.get_ip_pool()}
        finally:
            self._rotate_lock.release()

    def background_check_nodes(self):
        """后台实时维护 IP 池：周期性拉表 + 探测。"""
        # 启动后稍等，避免和首次 connect 抢资源；随后立刻建池
        for _ in range(5):
            if self._stop_event.is_set():
                return
            time.sleep(1)
        while not self._stop_event.is_set():
            if self.config.get("pool_enabled", True):
                try:
                    # 池偏小时强制重新拉表，尽量补家宽日本节点
                    with self._pool_lock:
                        size = len(self._ip_pool)
                    min_size = int(self.config.get("pool_min_size", 3))
                    self.refresh_ip_pool(force_fetch=(size < min_size))
                except Exception as e:
                    self.log(f"IP 池刷新失败: {e}")
            interval = int(self.config.get("pool_refresh_interval", 45))
            with self._pool_lock:
                size = len(self._ip_pool)
            min_size = int(self.config.get("pool_min_size", 3))
            if size < min_size:
                interval = min(interval, 20)
            interval = max(15, interval)
            for _ in range(interval):
                if self._stop_event.is_set():
                    return
                time.sleep(1)

    def _auto_update_loop(self):
        while not self._stop_event.is_set():
            interval_min = self.config.get("auto_update_interval", 0)
            if interval_min <= 0:
                self._auto_update_trigger.wait(3600)
                self._auto_update_trigger.clear()
                continue
            interval_sec = interval_min * 60
            self._auto_update_trigger.wait(interval_sec)
            self._auto_update_trigger.clear()
            if self._stop_event.is_set():
                break
            current_interval = self.config.get("auto_update_interval", 0)
            if current_interval <= 0:
                continue
            self.fetch_nodes()

    # ============ 切换节点 ============
    def _switch_to_next_available(self):
        self.log("准备切换节点...")
        success, msg = self.auto_connect_next()
        if success:
            self.log(f"切换成功: {msg}")
        else:
            self.log(f"切换失败: {msg}")

    # ============ 自动连接下一个节点（优先节点优先） ============
    def auto_connect_next(self):
        """
        自动连接下一个可用节点。
        策略：
        1. 如果设置了优先节点，始终优先从它们之中选择（跳过当前IP）。
        2. 若所有优先节点均不可用（连接失败或已在黑名单），则降级到普通节点列表。
        3. 普通节点按质量优选（Score/Speed/Ping/会话/uptime，默认可过滤劣质节点），
           并支持同子网优先与 TCP 预检。
        4. 限制最大尝试次数，防止风暴循环。
        """
        # 获取当前连接（或最后尝试）的IP
        last_ip = None
        if self.current_node:
            last_ip = self.current_node.get("ip")
        elif self.status["node_info"].get("ip"):
            last_ip = self.status["node_info"]["ip"]

        attempt_count = 0

        # ---------- 优先节点循环 ----------
        if self.preferred_nodes:
            self.log("正在尝试优先节点...")
            start_idx = 0
            if last_ip:
                for i, node in enumerate(self.preferred_nodes):
                    if node.get("ip") == last_ip:
                        start_idx = i + 1
                        break

            # 第一轮：尝试所有非当前IP且不在黑名单的优先节点
            for i in range(len(self.preferred_nodes)):
                if self._stop_event.is_set():
                    break
                if attempt_count >= MAX_CONNECT_ATTEMPTS:
                    self.log(f"已达到最大尝试次数 ({MAX_CONNECT_ATTEMPTS})，停止尝试")
                    return False, "达到最大尝试次数"
                idx = (start_idx + i) % len(self.preferred_nodes)
                node = self.preferred_nodes[idx]
                node_ip = node.get("ip", "")
                node_hostname = node.get("hostname", "未知")
                if node_ip == last_ip:
                    continue
                if node_ip in self._failed_ips:
                    continue
                attempt_count += 1
                self.log(f"尝试优先节点: {node_hostname} ({node_ip})")
                self._add_failed_ip(node_ip)
                if self.connect_node(node):
                    return True, node_hostname

            # 如果第一轮全部因为黑名单或失败而跳过，尝试临时清空黑名单再试一次
            self.log("优先节点全部跳过或失败，临时清空黑名单再尝试一次...")
            self._failed_ips.clear()
            for i in range(len(self.preferred_nodes)):
                if self._stop_event.is_set():
                    break
                if attempt_count >= MAX_CONNECT_ATTEMPTS:
                    break
                idx = (start_idx + i) % len(self.preferred_nodes)
                node = self.preferred_nodes[idx]
                node_ip = node.get("ip", "")
                node_hostname = node.get("hostname", "未知")
                if node_ip == last_ip:
                    continue
                attempt_count += 1
                self.log(f"再次尝试优先节点: {node_hostname} ({node_ip})")
                if self.connect_node(node):
                    return True, node_hostname

            self.log("所有优先节点均连接失败，降级到普通节点列表...")

        # ---------- 优先从实时 IP 池选择 ----------
        for round_i in range(2):  # 第一轮用现池；失败后强制重刷再试一轮
            pool_candidates = self.pick_from_pool(exclude_ips={last_ip} if last_ip else set())
            if not pool_candidates and round_i == 0:
                self.log("IP 池暂无可连节点，强制刷新后再试")
                try:
                    self.refresh_ip_pool(force_fetch=True)
                except Exception as e:
                    self.log(f"强制刷新失败: {e}")
                pool_candidates = self.pick_from_pool(exclude_ips={last_ip} if last_ip else set())

            if pool_candidates:
                self.log(f"使用 IP 池候选 {len(pool_candidates)} 个进行自动连接（第 {round_i + 1} 轮）")
                for node in pool_candidates:
                    if self._stop_event.is_set():
                        break
                    if attempt_count >= MAX_CONNECT_ATTEMPTS:
                        self.log(f"已达到最大尝试次数 ({MAX_CONNECT_ATTEMPTS})，停止尝试")
                        return False, "达到最大尝试次数"
                    attempt_count += 1
                    node_ip = node.get("ip", "")
                    node_hostname = node.get("hostname", "未知")
                    self.log(f"IP 池连接尝试: {node_hostname} ({node_ip})")
                    if self.connect_node(node):
                        return True, node_hostname
                    # connect_node 内部已 mark bad / 踢池
                if round_i == 0:
                    self.log("本轮池内节点均失败，强制刷新 IP 池后再试一轮")
                    try:
                        self.refresh_ip_pool(force_fetch=True)
                    except Exception as e:
                        self.log(f"强制刷新失败: {e}")
                    continue

            break

        # 出口质量过滤开启时，不允许回退到未检测节点（否则会连上美国/被标 VPN 的地址）
        if self.config.get("pool_require_residential", True) or self.config.get("pool_reject_hosting", True):
            self.log("自动连接失败：合格 IP 池暂无可用节点（日本家宽/低欺诈且能连上的太少）")
            return False, "合格 IP 池暂无可用节点"

        # ---------- 普通节点列表（按质量优选） ----------
        allowed = self._allowed_countries()
        if allowed is None:
            region = self.config.get("region") or "all"
            nodes = self.filter_nodes(region, viable_only=True, ranked=True)
        elif len(allowed) == 1:
            region = next(iter(allowed))
            nodes = self.filter_nodes(region, viable_only=True, ranked=True)
        else:
            nodes = [
                n for n in self.filter_nodes("all", viable_only=True, ranked=False)
                if (n.get("country_short") or "").upper() in allowed
            ]
            nodes = self.rank_nodes(nodes)
        if not nodes:
            self.log("自动连接失败：当前地区没有可用节点")
            return False, "当前地区没有可用节点"

        prefer_same_subnet = self.config.get("prefer_same_subnet", False)
        subnet_prefix = self.config.get("subnet_prefix_length", 24)

        # 收集候选节点（不在黑名单中且不是当前IP），已按质量降序
        candidates = []
        for node in nodes:
            node_ip = node.get("ip")
            if node_ip == last_ip:
                continue
            if node_ip in self._failed_ips:
                continue
            candidates.append(node)

        if not candidates:
            self.log("自动连接失败：没有其他可用节点")
            return False, "没有其他可用节点"

        # 同子网优先：同子网内仍按质量排序，再拼其他优质节点
        if prefer_same_subnet and last_ip:
            subnet_nodes = []
            other_nodes = []
            last_sub = self._get_subnet(last_ip, subnet_prefix)
            for node in candidates:
                node_sub = self._get_subnet(node.get("ip", ""), subnet_prefix)
                if node_sub and last_sub and node_sub == last_sub:
                    subnet_nodes.append(node)
                else:
                    other_nodes.append(node)
            candidates = self.rank_nodes(subnet_nodes) + self.rank_nodes(other_nodes)

        # 连接前做轻量探测，跳过明显不可达的 TCP 节点，减少劣质 IP 浪费尝试次数
        precheck = self.config.get("precheck_nodes", True)
        if precheck:
            probed = []
            for node in candidates:
                if self.test_node(node):
                    probed.append(node)
                else:
                    self.log(f"预检跳过低质/不可达节点: {node.get('hostname', '未知')} ({node.get('ip', '')})")
            if probed:
                candidates = probed
            else:
                self.log("预检后无剩余节点，回退到质量排序列表继续尝试")

        if candidates:
            top = candidates[0]
            self.log(
                f"优选候选 {len(candidates)} 个，首选: {top.get('hostname', '未知')} "
                f"({top.get('ip', '')}) score={top.get('score')} speed={top.get('speed')} ping={top.get('ping')}"
            )

        for node in candidates:
            if self._stop_event.is_set():
                break
            if attempt_count >= MAX_CONNECT_ATTEMPTS:
                self.log(f"已达到最大尝试次数 ({MAX_CONNECT_ATTEMPTS})，停止尝试")
                return False, "达到最大尝试次数"
            attempt_count += 1
            node_ip = node.get("ip", "")
            node_hostname = node.get("hostname", "未知")
            self._add_failed_ip(node_ip)
            self.log(f"自动连接尝试节点: {node_hostname} ({node_ip})")
            if self.connect_node(node):
                return True, node_hostname
            self.log(f"节点 {node_hostname} 连接失败")

        self.log("自动连接失败：所有候选节点均连接失败")
        return False, "所有候选节点均连接失败"

    def start(self):
        self._stop_event.clear()
        self._auto_update_trigger.clear()
        self._failed_ips.clear()
        self.fetch_nodes()

        # 先启动后台线程（健康检测、自动更新等），确保连接成功后能自动维护
        if not self._threads_started:
            self._threads_started = True
            self._health_thread = threading.Thread(target=self.health_check_loop, daemon=True)
            self._health_thread.start()
            self._bg_check_thread = threading.Thread(target=self.background_check_nodes, daemon=True)
            self._bg_check_thread.start()
            self._auto_update_thread = threading.Thread(target=self._auto_update_loop, daemon=True)
            self._auto_update_thread.start()
            self._history_clean_thread = threading.Thread(target=self._history_clean_loop, daemon=True)
            self._history_clean_thread.start()

        # 首次启动：持续尝试直到连接成功或收到停止信号
        round_count = 0
        while not self._stop_event.is_set():
            round_count += 1
            connected = False

            # 优先尝试优先节点
            if self.preferred_nodes:
                self.log(f"第 {round_count} 轮：尝试优先节点...")
                for node in self.preferred_nodes:
                    if self._stop_event.is_set():
                        break
                    self._add_failed_ip(node.get("ip", ""))
                    if self.connect_node(node):
                        connected = True
                        break
                    self.log(f"优先节点 {node.get('hostname', '未知')} 连接失败")

            # 只连合格 IP 池：日本、非代理/VPN、非机房，家宽优先
            if not connected and not self._stop_event.is_set():
                with self._pool_lock:
                    empty = len(self._ip_pool) == 0
                if empty:
                    self.log(f"第 {round_count} 轮：IP 池为空，先刷新后再连...")
                    try:
                        self.refresh_ip_pool(force_fetch=True)
                    except Exception as e:
                        self.log(f"IP 池刷新失败: {e}")
                nodes = self.pick_from_pool()
                if nodes:
                    self.log(f"第 {round_count} 轮：从合格 IP 池连接（共 {len(nodes)} 个）...")
                    attempt = 0
                    for node in nodes:
                        if self._stop_event.is_set():
                            break
                        if attempt >= MAX_CONNECT_ATTEMPTS:
                            self.log(f"已达到最大尝试次数 ({MAX_CONNECT_ATTEMPTS})")
                            break
                        if node.get("ip") in self._failed_ips:
                            continue
                        attempt += 1
                        if self.connect_node(node):
                            connected = True
                            break
                        self.log(f"节点 {node.get('hostname', '未知')} 连接失败，尝试下一个...")
                        time.sleep(1)
                else:
                    self.log("合格 IP 池暂无可用节点（日本家宽优先）")

            if connected:
                self.log("VPN 连接成功建立")
                break
            else:
                # 所有节点都失败，清空黑名单，等待后重试
                self._failed_ips.clear()
                retry_interval = self.config.get("reconnect_interval", 30)
                self.log(f"第 {round_count} 轮所有节点均连接失败，{retry_interval} 秒后重试...")
                self._stop_event.wait(retry_interval)

    def _get_subnet(self, ip, prefix_len=24):
        try:
            network = ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
            return network.network_address
        except Exception:
            return None

    def measure_nodes_latency(self, ips):
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def ping_ip(ip):
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "2", ip],
                    capture_output=True, text=True, timeout=5
                )
                if "time=" in result.stdout:
                    match = re.search(r"time=(\d+\.?\d*) ms", result.stdout)
                    if match:
                        return ip, round(float(match.group(1)), 1)
            except Exception:
                pass
            return ip, -1

        results = {}
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(ping_ip, ip) for ip in ips]
            for future in as_completed(futures):
                ip, lat = future.result()
                results[ip] = lat
        return results

    def stop(self):
        self._stop_event.set()
        self._auto_update_trigger.set()

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._state_lock:
            for rec in self.connection_history:
                if rec.get("end_time") is None:
                    rec["end_time"] = now_str
                    try:
                        start = datetime.strptime(rec["start_time"], "%Y-%m-%d %H:%M:%S")
                        duration = datetime.strptime(now_str, "%Y-%m-%d %H:%M:%S") - start
                        rec["duration"] = str(duration).split('.')[0]
                    except Exception:
                        pass
            self._save_history()

        self.disconnect()
        # 等待后台线程退出，避免重启时线程翻倍
        threads = [self._health_thread, self._bg_check_thread,
                   self._auto_update_thread, self._history_clean_thread]
        for t in threads:
            if t and t.is_alive():
                t.join(timeout=5)
        self._threads_started = False
