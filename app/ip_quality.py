"""IP 质量评分（对齐 fingerprint-manager 面板质量逻辑）。

免费源：PTR + Team Cymru ASN + 本地 ASN/PTR 规则。
可选：IPQS（config fraud_api_key + fraud_provider=ipqs）。

适配说明：本仓库候选本身来自 VPN Gate，故 vpngate_listed 只打标不硬淘；
opengw/softether 等 PTR、机房/商业 VPN ASN、Tor 仍硬淘。
"""
from __future__ import annotations

import json
import re
import socket
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

START_SCORE = 80
HARD_FAIL_CAP = 20
UNVERIFIED_CAP = 74
ANCHOR_SCORE = 74
QUALITY_TTL_SEC = 43200

# 常见云 / 机房 ASN（可扩展）
CLOUD_ASNS = {
    16509, 14618, 15169, 8075, 13335, 14061, 20473, 63949, 16276, 24940,
    31898, 45102, 45090, 37963, 55933, 132203, 60068, 9009, 62240, 212238,
    51167, 60781, 12876, 16265, 36351, 46606, 398101, 396982,
}

# 商业 VPN 常见 ASN（抽样，可扩展）
VPN_ASNS = {
    9009, 212238, 60068, 20473, 39351, 40676, 53667, 62240, 46562, 35916,
    8100, 13213, 24961, 51167, 16276,
}

# 日系家宽 ASN（KDDI/NTT/SoftBank 等，抽样）
JP_HOME_ASNS = {
    2516, 4713, 9605, 17676, 17511, 4725, 7506, 4685, 7522, 9607,
    18126, 18135, 7679, 2518, 2527, 17506, 9354, 10010,
}

RESIDENTIAL_PTR = re.compile(
    r"(?:\.|\b)(?:ip|adsl|fiber|ftth|pool|dyn|dynamic|dial|cpe|home|resident|"
    r"catv|cmnet|bb|broadband|user|cust|customer|neo|flets|hikari|"
    r"kddi|ocn|so-net|biglobe|plala)",
    re.I,
)
BAD_PTR = re.compile(
    r"(?:vps|cloud|server|dedicated|hosting|coloc|ovh|linode|digitalocean|"
    r"amazonaws|googleusercontent|azure|contabo|hetzner)",
    re.I,
)
VPNGATE_PTR = re.compile(r"(?:opengw\.net|vpngate|softether)", re.I)


def _clamp(n: float, lo: float = 0, hi: float = 100) -> int:
    return int(max(lo, min(hi, n)))


def grade_of(score: int) -> str:
    if score >= 85:
        return "S"
    if score >= 70:
        return "A"
    if score >= 50:
        return "B"
    if score >= 30:
        return "C"
    return "D"


def decision_of(grade: str) -> str:
    return {
        "S": "prefer",
        "A": "allow",
        "B": "limited",
        "C": "degrade",
        "D": "reject",
    }.get(grade, "reject")


class QualityEngine:
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self._cache: Dict[str, Tuple[float, dict]] = {}

    def check(self, ip: str, *, force: bool = False, vpngate_source: bool = True) -> dict:
        if not ip:
            return self._empty(ip, error="empty_ip")
        now = time.time()
        cached = self._cache.get(ip)
        if cached and not force and now - cached[0] < QUALITY_TTL_SEC:
            # 若新配了 IPQS，而旧缓存未走 IPQS，则强制重检
            use_ipqs = self._ipqs_enabled()
            if not (use_ipqs and not cached[1].get("quality_used_ipqs")):
                return cached[1]

        identity = self._collect_identity(ip)
        privacy = self._collect_privacy(ip, identity)
        flags: List[str] = []
        hard_fails: List[str] = []

        # VPN Gate 公开列表：本仓库候选本身来自该列表 → 只打标
        if vpngate_source:
            flags.append("vpngate_source")
        else:
            # 非本池场景可扩展真正的列表命中
            pass

        ptr = identity.get("ptr") or ""
        if ptr and VPNGATE_PTR.search(ptr):
            hard_fails.append("vpngate_ptr")
        if privacy.get("tor"):
            hard_fails.append("tor")

        asn = identity.get("asn")
        asn_type = identity.get("asn_type") or ""
        if asn in CLOUD_ASNS or (privacy.get("hosting") and asn_type == "hosting"):
            hard_fails.append("datacenter")
        if asn in VPN_ASNS:
            hard_fails.append("commercial_vpn_asn")

        result = self._evaluate(
            ip=ip,
            identity=identity,
            privacy=privacy,
            flags=flags,
            hard_fails=hard_fails,
        )
        self._cache[ip] = (now, result)
        return result

    def _ipqs_enabled(self) -> bool:
        provider = (self.config.get("fraud_provider") or "").strip().lower()
        key = (self.config.get("fraud_api_key") or self.config.get("ipqs_key") or "").strip()
        return provider == "ipqs" and bool(key)

    def _empty(self, ip: str, error: str = "") -> dict:
        return {
            "quality_ip": ip,
            "score": 0,
            "grade": "D",
            "decision": "reject",
            "quality_flags": [error] if error else [],
            "quality_hard_fails": ["error"],
            "profile_match": False,
            "profile_mismatch": ["error"],
        }

    def _collect_identity(self, ip: str) -> dict:
        ptr = self._lookup_ptr(ip)
        asn, asn_name, country = self._lookup_cymru(ip)
        asn_type = "unknown"
        if asn in CLOUD_ASNS:
            asn_type = "hosting"
        elif asn in VPN_ASNS:
            asn_type = "vpn"
        elif asn in JP_HOME_ASNS:
            asn_type = "isp"
        elif asn_name:
            name_l = asn_name.lower()
            if any(k in name_l for k in ("telecom", "broadband", "cable", "mobile", "通信", "電信")):
                asn_type = "isp"
            if any(k in name_l for k in ("mobile", "wireless", "cellular")):
                asn_type = "mobile"
            if any(k in name_l for k in ("cloud", "hosting", "server", "vps", "colo")):
                asn_type = "hosting"
        return {
            "ptr": ptr,
            "asn": asn,
            "asn_name": asn_name,
            "country": country,
            "asn_type": asn_type,
        }

    def _collect_privacy(self, ip: str, identity: dict) -> dict:
        privacy = {
            "vpn": False,
            "proxy": False,
            "residential_proxy": False,
            "hosting": False,
            "tor": False,
            "fraud_score": None,
            "recent_abuse": False,
            "used_ipqs": False,
            "used_ipinfo": False,
        }
        ptr = identity.get("ptr") or ""
        if ptr and VPNGATE_PTR.search(ptr):
            privacy["vpn"] = True
        if identity.get("asn") in CLOUD_ASNS or identity.get("asn_type") == "hosting":
            privacy["hosting"] = True
        if identity.get("asn") in VPN_ASNS:
            privacy["vpn"] = True

        if self._ipqs_enabled():
            ipqs = self._lookup_ipqs(ip)
            if ipqs:
                privacy["used_ipqs"] = True
                privacy["vpn"] = privacy["vpn"] or bool(ipqs.get("vpn"))
                privacy["proxy"] = privacy["proxy"] or bool(ipqs.get("proxy"))
                privacy["tor"] = privacy["tor"] or bool(ipqs.get("tor"))
                privacy["hosting"] = privacy["hosting"] or bool(ipqs.get("is_crawler") and False)
                # IPQS 常用字段
                privacy["fraud_score"] = ipqs.get("fraud_score")
                privacy["recent_abuse"] = bool(ipqs.get("recent_abuse"))
                if str(ipqs.get("connection_type") or "").lower() == "data center":
                    privacy["hosting"] = True
                if ipqs.get("active_vpn") or ipqs.get("vpn"):
                    privacy["vpn"] = True
                if ipqs.get("proxy"):
                    privacy["proxy"] = True
        return privacy

    def _evaluate(self, ip, identity, privacy, flags, hard_fails) -> dict:
        score = float(START_SCORE)
        bonuses = []
        penalties = []
        flags = list(flags)

        asn_type = identity.get("asn_type") or "unknown"
        ptr = identity.get("ptr") or ""
        asn = identity.get("asn")

        ptr_residential = bool(ptr and RESIDENTIAL_PTR.search(ptr))
        if ptr_residential:
            flags.append("ptr_residential")

        # bonuses
        if asn_type == "isp":
            score += 8
            bonuses.append("asn_isp+8")
        if asn_type == "mobile":
            score += 8
            bonuses.append("asn_mobile+8")
        if ptr_residential:
            score += 6
            bonuses.append("ptr_residential+6")

        used_paid = bool(privacy.get("used_ipqs") or privacy.get("used_ipinfo"))
        privacy_clean = used_paid and not any(
            privacy.get(k) for k in ("vpn", "proxy", "residential_proxy", "hosting", "tor")
        )
        if privacy_clean:
            score += 6
            bonuses.append("all_privacy_clean+6")

        fraud = privacy.get("fraud_score")
        if fraud is not None:
            try:
                fraud = int(fraud)
            except Exception:
                fraud = None
        if fraud is not None and fraud <= 10 and not privacy.get("vpn"):
            score += 5
            bonuses.append("ipqs_low_fraud+5")

        if asn in JP_HOME_ASNS and not privacy.get("vpn"):
            score += 4
            bonuses.append("jp_home_asn_clean+4")

        # penalties
        if privacy.get("vpn"):
            score -= 25
            penalties.append("vpn-25")
        if privacy.get("proxy"):
            score -= 20
            penalties.append("proxy-20")
        if privacy.get("residential_proxy"):
            score -= 15
            penalties.append("residential_proxy-15")
        if privacy.get("hosting") and "datacenter" not in hard_fails:
            score -= 30
            penalties.append("hosting-30")

        if fraud is not None:
            if fraud >= 75:
                score -= 35
                penalties.append("ipqs_fraud>=75-35")
            elif fraud >= 50:
                score -= 20
                penalties.append("ipqs_fraud>=50-20")
            elif fraud >= 25:
                score -= 10
                penalties.append("ipqs_fraud>=25-10")
        if privacy.get("recent_abuse"):
            score -= 15
            penalties.append("ipqs_recent_abuse-15")

        if asn_type in ("isp", "mobile") and any(
            privacy.get(k) for k in ("vpn", "proxy", "residential_proxy")
        ):
            score -= 10
            penalties.append("privacy_true_on_isp-10")

        if ptr and BAD_PTR.search(ptr) and "vpngate_ptr" not in hard_fails:
            score -= 15
            penalties.append("bad_ptr-15")

        # hard fail cap
        if hard_fails:
            score = min(score, HARD_FAIL_CAP)
            flags.extend(f"hard:{h}" for h in hard_fails)

        score = _clamp(score)

        # unverified privacy cap
        if not used_paid and not hard_fails:
            if score > UNVERIFIED_CAP:
                score = UNVERIFIED_CAP
                flags.append("unverified_privacy")

        grade = grade_of(score)
        decision = decision_of(grade)
        if hard_fails:
            grade = "D"
            decision = "reject"

        profile_match, mismatches = self._profile_match(
            score=score,
            grade=grade,
            decision=decision,
            hard_fails=hard_fails,
            asn_type=asn_type,
            ptr_residential=ptr_residential,
            ptr=ptr,
        )

        return {
            "quality_ip": ip,
            "score": score,
            "grade": grade,
            "decision": decision,
            "quality_flags": flags + bonuses + penalties,
            "quality_hard_fails": hard_fails,
            "quality_asn": asn,
            "quality_asn_name": identity.get("asn_name"),
            "quality_asn_type": asn_type,
            "quality_ptr": ptr,
            "quality_country": identity.get("country"),
            "profile_match": profile_match,
            "profile_mismatch": mismatches,
            "quality_used_ipqs": bool(privacy.get("used_ipqs")),
            "quality_used_ipinfo": bool(privacy.get("used_ipinfo")),
            "quality_fraud_score": fraud,
            "quality_checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def _profile_match(self, score, grade, decision, hard_fails, asn_type, ptr_residential, ptr):
        mismatches = []
        if decision == "reject" or grade == "D":
            mismatches.append("reject_or_D")
        grade_rank = {"S": 4, "A": 3, "B": 2, "C": 1, "D": 0}
        if grade_rank.get(grade, 0) < grade_rank["A"]:
            mismatches.append("grade<A")
        if score < ANCHOR_SCORE:
            mismatches.append(f"score<{ANCHOR_SCORE}")
        # 仅当已知为 hosting/vpn 时否；unknown/isp/mobile 通过
        if asn_type in ("hosting", "vpn"):
            mismatches.append("asn_type_not_isp_mobile")
        if not ptr_residential and not (ptr and RESIDENTIAL_PTR.search(ptr or "")):
            mismatches.append("no_residential_ptr")
        if hard_fails:
            mismatches.append("hard_fails")
        # 不限国家
        return (len(mismatches) == 0), mismatches

    @staticmethod
    def _lookup_ptr(ip: str) -> str:
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name or ""
        except Exception:
            return ""

    @staticmethod
    def _lookup_cymru(ip: str) -> Tuple[Optional[int], str, str]:
        """Team Cymru DNS whois: ASN / AS Name / CC"""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return None, "", ""
            qname = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.origin.asn.cymru.com"
            # dig via socket.getaddrinfo won't give TXT; use requests DNS-over-HTTPS as fallback-free?
            # Use dns query via subprocess dig if available, else HTTP to cymru whois
            import subprocess
            dig = subprocess.run(
                ["dig", "+short", qname, "TXT"],
                capture_output=True, text=True, timeout=5,
            )
            txt = (dig.stdout or "").strip().strip('"')
            # format: "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name" via full whois
            # origin TXT is like: "2516 | 121.109.224.0/24 | JP | apnic | 2006-..."
            if txt:
                fields = [x.strip() for x in txt.replace('"', "").split("|")]
                asn = int(fields[0]) if fields and fields[0].isdigit() else None
                cc = fields[2] if len(fields) > 2 else ""
                # AS name needs separate query
                asn_name = ""
                if asn:
                    dig2 = subprocess.run(
                        ["dig", "+short", f"AS{asn}.asn.cymru.com", "TXT"],
                        capture_output=True, text=True, timeout=5,
                    )
                    t2 = (dig2.stdout or "").strip().strip('"')
                    if t2:
                        f2 = [x.strip() for x in t2.replace('"', "").split("|")]
                        if len(f2) >= 5:
                            asn_name = f2[-1]
                        elif len(f2) >= 1:
                            asn_name = f2[-1]
                return asn, asn_name, cc.upper()
        except Exception:
            pass
        # fallback whois.cymru.com
        try:
            resp = requests.get(
                f"https://v4.whois.cymru.com/nolog/{ip}",
                timeout=6,
            )
            # not always JSON; try bulk whois TCP-like HTTP is unreliable
        except Exception:
            pass
        try:
            s = socket.create_connection(("whois.cymru.com", 43), timeout=6)
            s.sendall(f" -v {ip}\n".encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            s.close()
            lines = data.decode("utf-8", errors="ignore").strip().splitlines()
            # header + data
            for line in lines:
                if line.upper().startswith("AS") or "|" not in line:
                    continue
                fields = [x.strip() for x in line.split("|")]
                # AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
                if len(fields) >= 7 and fields[0].isdigit():
                    return int(fields[0]), fields[6], fields[3].upper()
                if len(fields) >= 1 and fields[0].isdigit():
                    cc = fields[3].upper() if len(fields) > 3 else ""
                    name = fields[6] if len(fields) > 6 else ""
                    return int(fields[0]), name, cc
        except Exception:
            pass
        return None, "", ""

    def _lookup_ipqs(self, ip: str) -> Optional[dict]:
        key = (self.config.get("fraud_api_key") or self.config.get("ipqs_key") or "").strip()
        if not key:
            return None
        try:
            url = f"https://ipqualityscore.com/api/json/ip/{key}/{ip}"
            resp = requests.get(
                url,
                params={
                    "strictness": 1,
                    "allow_public_access_points": "true",
                    "lighter_penalties": "true",
                },
                timeout=12,
            )
            data = resp.json() if resp.ok else {}
            if data.get("success") is False:
                return None
            return data
        except Exception:
            return None


def summarize_quality(q: dict) -> str:
    if not q:
        return "-"
    return f"{q.get('grade', '?')}/{q.get('score', 0)}"
