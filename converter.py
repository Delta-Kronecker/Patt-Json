import json
import requests
from urllib.parse import parse_qs, unquote, urlparse

URL = "https://github.com/patterniha/Free-Configs/raw/refs/heads/main/configs.txt"
OUT = "converted.json"

TEMPLATE = {
    "log": {"loglevel": "warning"},
    "dns": {
        "hosts": {
            "geosite:category-ads-all": "127.0.0.1",
            "domain:googleapis.cn": "googleapis.com",
            "dns.alidns.com": ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
            "dns.sse.cisco.com": ["208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53"],
            "dns.umbrella.com": ["208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53"],
            "one.one.one.one": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
            "1dot1dot1dot1.cloudflare-dns.com": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
            "dns.cloudflare.com": ["162.159.61.8", "172.64.41.8", "2a06:98c1:52::8", "2803:f800:53::8"],
            "cloudflare-dns.com": ["104.16.248.249", "104.16.249.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"],
            "engage.cloudflareclient.com": ["162.159.192.1", "2606:4700:d0::a29f:c001"],
            "doh.pub": ["1.12.12.12", "120.53.53.53"],
            "dot.pub": ["1.12.12.12", "120.53.53.53"],
            "dns.google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
            "dns.quad9.net": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
            "dns.sb": ["45.11.45.11", "185.222.222.222", "2a09::", "2a11::"],
            "common.dot.dns.yandex.net": ["77.88.8.8", "77.88.8.1", "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"]
        },
        "servers": [
            {"address": "fakedns", "domains": ["geosite:cn", "geosite:private", "domain:ir", "geosite:category-ir"]},
            "https://dns.google/dns-query",
            {"address": "localhost", "domains": ["geosite:private"], "finalQuery": True, "skipFallback": True, "tag": "domestic-dns_1_0"},
            {"address": "localhost", "domains": ["domain:ir", "geosite:category-ir"], "finalQuery": True, "skipFallback": True, "tag": "domestic-dns_2_0"}
        ],
        "tag": "dns-module"
    },
    "inbounds": [{
        "tag": "socks",
        "listen": "127.0.0.1",
        "port": 10808,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True},
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic", "fakedns"],
            "routeOnly": False
        }
    }],
    "policy": {
        "levels": {
            "0": {"downlinkOnly": 0, "uplinkOnly": 0},
            "12": {"connIdle": 12, "downlinkOnly": 0, "uplinkOnly": 0}
        },
        "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}
    },
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {"inboundTag": ["socks"], "port": "53", "outboundTag": "dns-out"},
            {"inboundTag": ["domestic-dns_1_0", "domestic-dns_2_0"], "outboundTag": "direct"},
            {"inboundTag": ["dns-module"], "outboundTag": "proxy"},
            {"protocol": ["bittorrent"], "outboundTag": "direct"},
            {"network": "udp", "port": "443", "outboundTag": "block"},
            {"domain": ["geosite:category-ads-all"], "outboundTag": "block"},
            {"ip": ["geoip:private"], "outboundTag": "direct"},
            {"domain": ["geosite:private"], "outboundTag": "direct"},
            {"domain": ["domain:ir", "geosite:category-ir"], "outboundTag": "direct"},
            {"ip": ["geoip:ir"], "outboundTag": "direct"}
        ]
    },
    "stats": {}
}

TAIL_OUTBOUNDS = [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"},
    {"tag": "dns-out", "protocol": "dns", "settings": {"userLevel": 12}}
]


def build_stream(q):
    network = q.get("type", ["tcp"])[0]
    security = q.get("security", ["none"])[0]

    stream = {
        "network": network,
        "security": security
    }

    if security == "tls":
        tls = {}
        sni = q.get("sni", [""])[0]
        if sni:
            tls["serverName"] = sni
        alpn = q.get("alpn", [""])[0]
        if alpn:
            tls["alpn"] = [a for a in alpn.split(",") if a]
        fp = q.get("fp", [""])[0]
        if fp:
            tls["fingerprint"] = fp
        if q.get("cs"):
            tls["cipherSuites"] = q["cs"][0]
        if q.get("allowInsecure", ["0"])[0] == "1":
            tls["allowInsecure"] = True
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
        stream["realitySettings"] = reality

    if network == "ws":
        ws = {"path": unquote(q.get("path", ["/"])[0])}
        host = q.get("host", [""])[0]
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws

    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", [""])[0]}
        if q.get("authority"):
            stream["grpcSettings"]["authority"] = q["authority"][0]

    elif network == "tcp":
        header_type = q.get("headerType", ["none"])[0]
        if header_type and header_type != "none":
            stream["tcpSettings"] = {
                "header": {
                    "type": header_type,
                    "request": {
                        "path": [unquote(q.get("path", ["/"])[0])],
                        "headers": {"Host": q.get("host", [""])[0]}
                    }
                }
            }

    elif network == "xhttp":
        xhttp = {"path": unquote(q.get("path", ["/"])[0])}
        if q.get("host"):
            xhttp["host"] = q["host"][0]
        if q.get("mode"):
            xhttp["mode"] = q["mode"][0]
        stream["xhttpSettings"] = xhttp

    elif network == "httpupgrade":
        hu = {"path": unquote(q.get("path", ["/"])[0])}
        if q.get("host"):
            hu["host"] = q["host"][0]
        stream["httpupgradeSettings"] = hu

    if q.get("fm"):
        raw = unquote(q["fm"][0])
        try:
            stream["finalmask"] = json.loads(raw)
        except Exception:
            stream["finalmask"] = raw

    sockopt = {}
    if q.get("tcpNoDelay", ["0"])[0] == "1":
        sockopt["tcpNoDelay"] = True
    if sockopt:
        stream["sockopt"] = sockopt

    return stream


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

    proxy = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": p.hostname or "",
                "port": p.port or 443,
                "users": [user]
            }]
        },
        "streamSettings": build_stream(q)
    }
    return proxy, unquote(p.fragment) if p.fragment else ""


def parse_trojan(uri):
    p = urlparse(uri)
    q = parse_qs(p.query)
    proxy = {
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": p.hostname or "",
                "port": p.port or 443,
                "password": unquote(p.username) if p.username else ""
            }]
        },
        "streamSettings": build_stream(q)
    }
    return proxy, unquote(p.fragment) if p.fragment else ""


def main():
    text = requests.get(URL, timeout=30).text
    configs = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("vless://"):
                proxy, remark = parse_vless(line)
            elif line.startswith("trojan://"):
                proxy, remark = parse_trojan(line)
            else:
                continue
            configs.append({"remarks": remark, "proxy": proxy})
        except Exception:
            pass

    result = {
        "template": TEMPLATE,
        "tailOutbounds": TAIL_OUTBOUNDS,
        "configs": configs
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, separators=(",", ":"))

    print(f"done: {len(configs)} configs -> {OUT}")


if __name__ == "__main__":
    main()
