import json
import os
import secrets
import tempfile

CONFIG_PATH = "/data/config.json"

DEFAULT_CONFIG = {
    "web_password": "admin",
    "api_url": "",
    "socks_port": 1080,
    "web_port": 8080,
    "vpn_user": "",
    "vpn_pass": "",
    "region": "JP",
    "node_limit": 200,
    "check_limit": 20,
    "secret_key": "",
    "auto_update_interval": 5,
    "health_fail_threshold": 3,
    "health_check_interval": 10,
    "log_retention_days": 3,
    "health_check_urls": "",
    "latency_check_target": "",
    "speedtest_url": "http://cachefly.cachefly.net/1mb.test",
    "speedtest_retry": 3,
    "prefer_same_subnet": False,
    "subnet_prefix_length": 24,
    "health_check_timeout": 8,
    "preferred_nodes": [],
    # 优选 IP / 节点质量
    "prefer_quality_sort": True,
    "filter_low_quality": True,
    "precheck_nodes": True,
    "node_probe_timeout": 2.5,
    "min_node_score": 0,
    "min_node_speed": 0,
    "max_node_ping": 0,
    "max_node_sessions": 0,
    # 默认略抬高 JP（参考优质住宅线如 KDDI 121.109.x），可在设置里改成 [] 或其它国家
    "quality_boost_countries": ["JP"],
    "connection_history_retention_days": 30,
    "socks_max_connections": 200,
    "reconnect_interval": 30,
    # IP 池：后台实时探测维护，程序通过 API 换出口
    "pool_enabled": True,
    "pool_refresh_interval": 45,
    "pool_probe_limit": 0,
    "pool_max_size": 100,
    "api_token": "",
    # 出口质量：日本 + 家宽为主；代理标记可放行；欺诈分可选
    "pool_country": "JP",
    "pool_reject_proxy": False,
    "pool_reject_hosting": True,
    "pool_reject_mobile": True,
    "pool_prefer_residential": True,
    "pool_require_residential": True,
    "pool_geo_cache_ttl": 21600,
    "pool_min_size": 3,
    "pool_verify_exit_geo": True,
    "openvpn_connect_timeout": 18,
    # 欺诈/纯净度：配了 key 才启用。provider: ipqs | proxycheck | none
    "fraud_provider": "none",
    "fraud_api_key": "",
    "max_fraud_score": 75,
    "fraud_hard_filter": False,
    "fraud_cache_ttl": 86400,
}

# 不应通过 API 返回给前端的敏感字段
SENSITIVE_KEYS = {"web_password", "vpn_pass", "secret_key", "api_token", "fraud_api_key"}


def load_config():
    if not os.path.exists(CONFIG_PATH):
        cfg = DEFAULT_CONFIG.copy()
        cfg["secret_key"] = secrets.token_hex(24)
        cfg["api_token"] = secrets.token_hex(16)
        save_config(cfg)
        return cfg
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    if not cfg.get("secret_key"):
        cfg["secret_key"] = secrets.token_hex(24)
        save_config(cfg)
    if not cfg.get("api_token"):
        cfg["api_token"] = secrets.token_hex(16)
        save_config(cfg)
    return cfg


def save_config(cfg):
    """原子写入：先写临时文件再 rename，防止写入中途崩溃导致配置损坏"""
    dir_name = os.path.dirname(CONFIG_PATH) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, CONFIG_PATH)  # 原子替换
    except Exception:
        # 清理临时文件
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def get_safe_config(cfg=None):
    """返回脱敏后的配置（隐藏密码和密钥）"""
    if cfg is None:
        cfg = load_config()
    safe = {}
    for k, v in cfg.items():
        if k in SENSITIVE_KEYS:
            safe[k] = "******" if v else ""
        else:
            safe[k] = v
    return safe
