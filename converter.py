import json
import requests
from urllib.parse import parse_qs, unquote, urlparse

URL = "https://github.com/patterniha/Free-Configs/raw/refs/heads/main/configs.txt"
OUT = "converted.json"

def parse_vless(uri):
    p = urlparse(uri)
    q = parse_qs(p.query)
    return {
        "protocol": "vless",
        "remark": unquote(p.fragment) if p.fragment else "",
        "address": p.hostname or "",
        "port": p.port or 443,
        "uuid": unquote(p.username) if p.username else "",
        "flow": q.get("flow", [""])[0],
        "security": q.get("security", [""])[0],
        "network": q.get("type", ["tcp"])[0],
        "host": q.get("host", [""])[0],
        "path": unquote(q.get("path", ["/"])[0]),
        "sni": q.get("sni", [""])[0],
        "alpn": q.get("alpn", [""])[0],
        "fingerprint": q.get("fp", [""])[0],
        "publicKey": q.get("pbk", [""])[0],
        "shortId": q.get("sid", [""])[0],
        "spiderX": q.get("spx", [""])[0],
    }

def parse_trojan(uri):
    p = urlparse(uri)
    q = parse_qs(p.query)
    return {
        "protocol": "trojan",
        "remark": unquote(p.fragment) if p.fragment else "",
        "address": p.hostname or "",
        "port": p.port or 443,
        "password": unquote(p.username) if p.username else "",
        "security": q.get("security", [""])[0],
        "network": q.get("type", ["tcp"])[0],
        "host": q.get("host", [""])[0],
        "path": unquote(q.get("path", ["/"])[0]),
        "sni": q.get("sni", [""])[0],
        "alpn": q.get("alpn", [""])[0],
        "fingerprint": q.get("fp", [""])[0],
        "cipherSuites": q.get("cs", [""])[0],
        "finalmask": q.get("fm", [""])[0],
    }

def main():
    text = requests.get(URL, timeout=30).text
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("vless://"):
            try:
                out.append(parse_vless(line))
            except Exception:
                pass
        elif line.startswith("trojan://"):
            try:
                out.append(parse_trojan(line))
            except Exception:
                pass
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
