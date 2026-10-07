import json
import requests
from urllib.parse import parse_qs, unquote, urlparse

URL = "https://github.com/patterniha/Free-Configs/raw/refs/heads/main/configs.txt"
OUT = "converted.json"


def build_stream(q, host_default=""):
    network = q.get("type", ["tcp"])[0]
    security = q.get("security", ["none"])[0]
    host = q.get("host", [host_default])[0] or host_default
    path = unquote(q.get("path", ["/"])[0])

    stream = {"network": network}

    if network == "ws":
        stream["wsSettings"] = {
            "host": host,
            "path": path
        }
    elif network == "grpc":
        grpc = {"serviceName": q.get("serviceName", [""])[0]}
        if q.get("authority"):
            grpc["authority"] = q["authority"][0]
        stream["grpcSettings"] = grpc
    elif network == "tcp":
        header_type = q.get("headerType", ["none"])[0]
        if header_type and header_type != "none":
            stream["tcpSettings"] = {
                "header": {
                    "type": header_type,
                    "request": {
                        "path": [path],
                        "headers": {"Host": host}
                    }
                }
            }
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": host}
    elif network == "xhttp":
        xhttp = {"path": path}
        if host:
            xhttp["host"] = host
        if q.get("mode"):
            xhttp["mode"] = q["mode"][0]
        stream["xhttpSettings"] = xhttp

    if security == "tls":
        tls = {}
        sni = q.get("sni", [""])[0]
        if sni:
            tls["serverName"] = sni
        fp = q.get("fp", [""])[0]
        if fp:
            tls["fingerprint"] = fp
        alpn = q.get("alpn", [""])[0]
        if alpn:
            tls["alpn"] = [a for a in alpn.split(",") if a]
        if q.get("cs"):
            tls["cipherSuites"] = q["cs"][0]
        if q.get("allowInsecure", ["0"])[0] == "1":
            tls["allowInsecure"] = True
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality = {}
        sni = q.get("sni", [""])[0]
        if sni:
            reality["serverName"] = sni
        fp = q.get("fp", [""])[0]
        if fp:
            reality["fingerprint"] = fp
        if q.get("pbk"):
            reality["publicKey"] = q["pbk"][0]
        if q.get("sid"):
            reality["shortId"] = q["sid"][0]
        if q.get("spx"):
            reality["spiderX"] = unquote(q["spx"][0])
        stream["security"] = "reality"
        stream["realitySettings"] = reality
    else:
        stream["security"] = "none"

    if q.get("fm"):
        raw = unquote(q["fm"][0])
        try:
            stream["finalmask"] = json.loads(raw)
        except Exception:
            stream["finalmask"] = raw

    return stream


def make_config(proxy, remark, is_best=False, all_proxies=None):
    cfg = {
        "remarks": remark,
        "version": {"min": "26.2.6"},
        "log": {"loglevel": "none"},
        "dns": {
            "servers": [
                "fakedns",
                {"address": "https://8.8.8.8/dns-query", "tag": "remote-dns"}
            ],
            "queryStrategy": "UseIP",
            "tag": "dns"
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "mixed",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "destOverride": ["http", "tls", "fakedns"],
                    "enabled": True,
                    "routeOnly": True
                },
                "tag": "mixed-in"
            },
            {
                "listen": "127.0.0.1",
                "port": 10853,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "1.1.1.1",
                    "network": "tcp,udp",
                    "port": 53
                },
                "tag": "dns-in"
            }
        ],
        "outbounds": [],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": []
        },
        "policy": {
            "levels": {
                "0": {
                    "connIdle": 300,
                    "handshake": 4,
                    "uplinkOnly": 1,
                    "downlinkOnly": 1
                }
            },
            "system": {
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True
            }
        },
        "stats": {}
    }

    if not is_best:
        cfg["outbounds"] = [
            proxy,
            {"protocol": "dns", "settings": {"rules": [{"action": "hijack"}]}, "tag": "dns-out"},
            {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
            {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
        ]
        cfg["routing"]["rules"] = [
            {"inboundTag": ["mixed-in"], "port": 53, "outboundTag": "dns-out", "type": "field"},
            {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
            {"inboundTag": ["remote-dns"], "outboundTag": "proxy", "type": "field"},
            {"inboundTag": ["dns"], "outboundTag": "direct", "type": "field"},
            {"domain": ["geosite:private"], "outboundTag": "direct", "type": "field"},
            {"ip": ["geoip:private"], "outboundTag": "direct", "type": "field"},
            {"network": "udp", "outboundTag": "block", "type": "field"},
            {"network": "tcp", "outboundTag": "proxy", "type": "field"}
        ]
    else:
        outs = []
        for i, p in enumerate(all_proxies, 1):
            p2 = json.loads(json.dumps(p))
            p2["tag"] = f"proxy-{i}"
            outs.append(p2)
        outs.append({"protocol": "dns", "settings": {"rules": [{"action": "hijack"}]}, "tag": "dns-out"})
        outs.append({"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"})
        outs.append({"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"})
        cfg["outbounds"] = outs

        cfg["routing"]["rules"] = [
            {"inboundTag": ["mixed-in"], "port": 53, "outboundTag": "dns-out", "type": "field"},
            {"inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field"},
            {"inboundTag": ["remote-dns"], "balancerTag": "all-proxies", "type": "field"},
            {"inboundTag": ["dns"], "outboundTag": "direct", "type": "field"},
            {"domain": ["geosite:private"], "outboundTag": "direct", "type": "field"},
            {"ip": ["geoip:private"], "outboundTag": "direct", "type": "field"},
            {"network": "udp", "outboundTag": "block", "type": "field"},
            {"network": "tcp", "balancerTag": "all-proxies", "type": "field"}
        ]
        cfg["routing"]["balancers"] = [{
            "tag": "all-proxies",
            "selector": ["proxy"],
            "strategy": {"type": "leastPing"},
            "fallbackTag": "proxy-2"
        }]
        cfg["observatory"] = {
            "subjectSelector": ["proxy"],
            "probeUrl": "https://www.gstatic.com/generate_204",
            "probeInterval": "30s",
            "enableConcurrency": True
        }

    return cfg


def parse_vless(uri):
    p = urlparse(uri)
    q = parse_qs(p.query)
    user = {
        "id": unquote(p.username) if p.username else "",
        "encryption": "none"
    }
    flow = q.get("flow", [""])[0]
    if flow:
        user["flow"] = flow

    host = p.hostname or ""
    proxy = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": p.port or 443,
                "users": [user]
            }]
        },
        "streamSettings": build_stream(q, host),
        "tag": "proxy"
    }
    return proxy, unquote(p.fragment) if p.fragment else ""


def parse_trojan(uri):
    p = urlparse(uri)
    q = parse_qs(p.query)
    host = p.hostname or ""
    proxy = {
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": host,
                "port": p.port or 443,
                "password": unquote(p.username) if p.username else ""
            }]
        },
        "streamSettings": build_stream(q, host),
        "tag": "proxy"
    }
    return proxy, unquote(p.fragment) if p.fragment else ""


def main():
    text = requests.get(URL, timeout=30).text

    vless_list = []
    trojan_list = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("vless://"):
                proxy, remark = parse_vless(line)
                vless_list.append((proxy, remark))
            elif line.startswith("trojan://"):
                proxy, remark = parse_trojan(line)
                trojan_list.append((proxy, remark))
        except Exception:
            pass

    result = []

    # VLESS: 1=domain(اسم دامنه اصلی) + بعدی‌ها IP
    for i, (proxy, remark) in enumerate(vless_list, 1):
        title = remark if remark else f"VLESS {i}"
        result.append(make_config(proxy, title))

    # Trojan
    for i, (proxy, remark) in enumerate(trojan_list, 1):
        title = remark if remark else f"Trojan {i}"
        result.append(make_config(proxy, title))

    # Best Ping (اگه حداقل ۲ پروکسی داشتیم)
    all_proxies = [p for p, _ in vless_list] + [p for p, _ in trojan_list]
    if len(all_proxies) >= 2:
        result.append(make_config(None, "Best Ping 🚀", is_best=True, all_proxies=all_proxies))

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=4)

    print(f"done: {len(result)} configs -> {OUT}")


if __name__ == "__main__":
    main()
