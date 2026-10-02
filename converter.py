import json
import requests
from urllib.parse import parse_qs, unquote, urlparse

URL = "https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/main/config/patt/protocols/trojan.txt"
OUT = "converted.json"

DNS = {
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
}

INBOUNDS = [{
    "listen": "127.0.0.1",
    "port": 10808,
    "protocol": "socks",
    "settings": {"auth": "noauth", "udp": True},
    "sniffing": {"destOverride": ["http", "tls", "quic", "fakedns"], "enabled": True, "routeOnly": False},
    "tag": "socks"
}]

POLICY = {
    "levels": {
        "0": {"downlinkOnly": 0, "uplinkOnly": 0},
        "12": {"connIdle": 12, "downlinkOnly": 0, "uplinkOnly": 0}
    },
    "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}
}

ROUTING = {
    "domainStrategy": "AsIs",
    "rules": [
        {"inboundTag": ["socks"], "outboundTag": "dns-out", "port": "53", "type": "field"},
        {"inboundTag": ["domestic-dns_1_0", "domestic-dns_2_0"], "outboundTag": "direct", "type": "field"},
        {"inboundTag": ["dns-module"], "outboundTag": "proxy", "type": "field"},
        {"outboundTag": "direct", "protocol": ["bittorrent"], "type": "field"},
        {"network": "udp", "outboundTag": "block", "port": "443", "type": "field"},
        {"domain": ["geosite:category-ads-all"], "outboundTag": "block", "type": "field"},
        {"ip": ["ext:geoip-only-cn-private.dat:private"], "outboundTag": "direct", "type": "field"},
        {"domain": ["geosite:private"], "outboundTag": "direct", "type": "field"},
        {"domain": ["domain:ir", "geosite:category-ir"], "outboundTag": "direct", "type": "field"},
        {"ip": ["geoip:ir"], "outboundTag": "direct", "type": "field"}
    ]
}


def build_stream(q):
    network = q.get("type", ["tcp"])[0]
    security = q.get("security", ["none"])[0]
    stream = {"network": network, "security": security}

    if security == "tls":
        tls = {
            "allowInsecure": q.get("allowInsecure", ["0"])[0] == "1",
            "serverName": q.get("sni", [""])[0]
        }
        alpn = q.get("alpn", [""])[0]
        if alpn:
            tls["alpn"] = alpn.split(",")
        fp = q.get("fp", [""])[0]
        if fp:
            tls["fingerprint"] = fp
        if q.get("cs"):
            tls["cipherSuites"] = q["cs"][0]
        stream["tlsSettings"] = tls

    if network == "ws":
        stream["wsSettings"] = {
            "host": q.get("host", [""])[0],
            "path": unquote(q.get("path", ["/"])[0])
        }

    if q.get("fm"):
        try:
            stream["finalmask"] = json.loads(unquote(q["fm"][0]))
        except Exception:
            pass

    return stream


def parse_vless(uri):
    p = urlparse(uri)
    q = parse_qs(p.query)
    outbound = {
        "mux": {"concurrency": -1, "enabled": False},
        "protocol": "vless",
        "settings": {
            "address": p.hostname or "",
            "port": p.port or 443,
            "id": unquote(p.username) if p.username else "",
            "encryption": "none"
        },
        "streamSettings": build_stream(q),
        "tag": "proxy"
    }
    return outbound, unquote(p.fragment) if p.fragment else ""


def parse_trojan(uri):
    p = urlparse(uri)
    q = parse_qs(p.query)
    outbound = {
        "mux": {"concurrency": -1, "enabled": False},
        "protocol": "trojan",
        "settings": {
            "address": p.hostname or "",
            "port": p.port or 443,
            "password": unquote(p.username) if p.username else ""
        },
        "streamSettings": build_stream(q),
        "tag": "proxy"
    }
    return outbound, unquote(p.fragment) if p.fragment else ""


def build_config(outbound, remark):
    return {
        "dns": DNS,
        "inbounds": INBOUNDS,
        "log": {"loglevel": "warning"},
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
            {"protocol": "dns", "settings": {"userLevel": 12}, "tag": "dns-out"}
        ],
        "policy": POLICY,
        "remarks": remark,
        "routing": ROUTING,
        "stats": {}
    }


def main():
    text = requests.get(URL, timeout=30).text
    results = []
    for line in text.splitlines():
        line = line.strip()
        try:
            if line.startswith("vless://"):
                ob, remark = parse_vless(line)
                results.append(build_config(ob, remark))
            elif line.startswith("trojan://"):
                ob, remark = parse_trojan(line)
                results.append(build_config(ob, remark))
        except Exception:
            pass
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
