#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VLESS & Hysteria 2 Link Extractor
Extracts vless:// and hysteria2:// links from subscription URLs,
Base64 strings, files, and Sing-Box / Xray JSON configurations.
"""

import sys
import re
import json
import base64
import hashlib
import urllib.request
import urllib.error
import urllib.parse
import argparse
from typing import List, Tuple

VLESS_REGEX = re.compile(r"vless://[^\s\"\'<>]+")
HY2_REGEX = re.compile(r"(?:hysteria2|hy2)://[^\s\"\'<>]+")

USER_AGENTS = [
    "v2rayN/6.40",
    "curl/8.23.0",
    "sing-box/1.9.0",
    "NekoBox/1.3.0",
]

def get_deterministic_hwid(url_str: str) -> str:
    h = hashlib.sha256(f"hwid_salt:{url_str}".encode()).hexdigest()
    return h[:32]

def fetch_url(url: str, hwid: str, insecure: bool = False) -> str:
    import ssl
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    last_err = None
    for ua in USER_AGENTS:
        try:
            headers = {
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Language": "ru,en;q=0.9",
            }
            if hwid:
                headers["x-hwid"] = hwid
                headers["x-device-os"] = "Windows"

            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
                if resp.status == 200:
                    data = resp.read()
                    return data.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            last_err = e
            continue
        except Exception as e:
            last_err = e
            break

    raise Exception(f"Failed to fetch URL: {last_err}")

def try_decode_base64(text: str) -> str:
    clean = re.sub(r"\s+", "", text)
    if len(clean) < 4:
        return ""

    missing_padding = len(clean) % 4
    if missing_padding:
        clean += "=" * (4 - missing_padding)

    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = fn(clean.encode("ascii", errors="ignore"))
            decoded_text = decoded.decode("utf-8")
            if any(c in decoded_text for c in ("vless://", "hysteria", "vmess://", "trojan://", "ss://", "outbounds")):
                return decoded_text
        except Exception:
            continue
    return ""

def parse_xray_json(content: str) -> Tuple[List[str], List[str]]:
    vless_links = []
    hy2_links = []
    try:
        data = json.loads(content)
        items = data if isinstance(data, list) else [data]

        for item in items:
            if not isinstance(item, dict):
                continue
            remarks = item.get("remarks", "")
            outbounds = item.get("outbounds", [])
            if not isinstance(outbounds, list):
                continue

            for ob in outbounds:
                if not isinstance(ob, dict):
                    continue
                proto = ob.get("protocol")
                tag = remarks or ob.get("tag", "")

                settings = ob.get("settings", {})
                ss = ob.get("streamSettings", {})

                if proto == "vless":
                    network = ss.get("network", "tcp")
                    security = ss.get("security", "none")
                    vnext = settings.get("vnext", [])
                    for vn in vnext:
                        address = vn.get("address")
                        port = vn.get("port", 443)
                        if not address or address == "0.0.0.0":
                            continue
                        for u in vn.get("users", []):
                            uuid = u.get("id")
                            if not uuid or uuid == "00000000-0000-0000-0000-000000000000":
                                continue
                            params = {"encryption": u.get("encryption", "none")}
                            if u.get("flow"): params["flow"] = u.get("flow")
                            params["type"] = network
                            params["security"] = security

                            if security == "reality":
                                rs = ss.get("realitySettings", {})
                                if rs.get("serverName"): params["sni"] = rs["serverName"]
                                if rs.get("publicKey"): params["pbk"] = rs["publicKey"]
                                if rs.get("shortId"): params["sid"] = rs["shortId"]
                                if rs.get("fingerprint"): params["fp"] = rs["fingerprint"]
                                if rs.get("spiderX"): params["spx"] = rs["spiderX"]
                            elif security == "tls":
                                ts = ss.get("tlsSettings", {})
                                if ts.get("serverName"): params["sni"] = ts["serverName"]
                                if ts.get("fingerprint"): params["fp"] = ts["fingerprint"]

                            if network == "ws":
                                ws = ss.get("wsSettings", {})
                                if ws.get("path"): params["path"] = ws["path"]
                                if ws.get("headers", {}).get("Host"): params["host"] = ws["headers"]["Host"]
                            elif network == "grpc":
                                gs = ss.get("grpcSettings", {})
                                if gs.get("serviceName"): params["serviceName"] = gs["serviceName"]
                            elif network in ("xhttp", "splithttp"):
                                xs = ss.get("xhttpSettings", {})
                                if xs.get("path"): params["path"] = xs["path"]
                                if xs.get("host"): params["host"] = xs["host"]
                                if xs.get("mode"): params["mode"] = xs["mode"]

                            final_tag = tag or address
                            qs = urllib.parse.urlencode(params)
                            vless_links.append(f"vless://{uuid}@{address}:{port}?{qs}#{urllib.parse.quote(final_tag)}")

                elif proto in ("hysteria", "hysteria2"):
                    addr = settings.get("address")
                    port = settings.get("port", 443)
                    if not addr or addr == "0.0.0.0":
                        continue
                    hs = ss.get("hysteriaSettings", {})
                    auth = hs.get("auth", settings.get("auth", ""))
                    tls = ss.get("tlsSettings", {})
                    sni = tls.get("serverName", addr)
                    q = {"sni": sni}
                    if tls.get("alpn"):
                        q["alpn"] = ",".join(tls["alpn"])
                    final_tag = tag or addr
                    auth_prefix = f"{auth}@" if auth else ""
                    qs = urllib.parse.urlencode(q)
                    hy2_links.append(f"hysteria2://{auth_prefix}{addr}:{port}/?{qs}#{urllib.parse.quote(final_tag)}")
    except Exception:
        pass
    return vless_links, hy2_links

def parse_singbox_json(content: str) -> Tuple[List[str], List[str]]:
    vless_links = []
    hy2_links = []
    try:
        data = json.loads(content)
        outbounds = data.get("outbounds", [])
        if not isinstance(outbounds, list):
            return [], []

        for ob in outbounds:
            if not isinstance(ob, dict):
                continue
            server = ob.get("server")
            port = ob.get("server_port", 443)
            tag = ob.get("tag", server)
            if not server or server == "0.0.0.0":
                continue

            ob_type = ob.get("type")
            if ob_type == "vless":
                uuid = ob.get("uuid")
                if not uuid or uuid == "00000000-0000-0000-0000-000000000000":
                    continue
                query = {"encryption": "none"}
                if ob.get("flow"): query["flow"] = ob["flow"]
                transport = ob.get("transport", {})
                query["type"] = transport.get("type", ob.get("network", "tcp"))
                if "path" in transport: query["path"] = transport["path"]
                if "host" in transport: query["host"] = transport["host"]

                tls = ob.get("tls", {})
                if tls.get("enabled"):
                    reality = tls.get("reality", {})
                    if reality.get("enabled"):
                        query["security"] = "reality"
                        if "public_key" in reality: query["pbk"] = reality["public_key"]
                        if "short_id" in reality: query["sid"] = reality["short_id"]
                    else:
                        query["security"] = "tls"
                    if "server_name" in tls: query["sni"] = tls["server_name"]
                    utls = tls.get("utls", {})
                    if utls.get("fingerprint"): query["fp"] = utls["fingerprint"]
                else:
                    query["security"] = "none"

                vless_links.append(f"vless://{uuid}@{server}:{port}?{urllib.parse.urlencode(query)}#{urllib.parse.quote(tag)}")

            elif ob_type in ("hysteria2", "hysteria"):
                auth = ob.get("password", ob.get("auth_str", ""))
                tls = ob.get("tls", {})
                sni = tls.get("server_name", server)
                q = {"sni": sni}
                if tls.get("insecure"): q["insecure"] = "1"
                auth_prefix = f"{auth}@" if auth else ""
                hy2_links.append(f"hysteria2://{auth_prefix}{server}:{port}/?{urllib.parse.urlencode(q)}#{urllib.parse.quote(tag)}")
    except Exception:
        pass
    return vless_links, hy2_links

def extract_all_links(raw_text: str) -> Tuple[List[str], List[str]]:
    vless_seen, hy2_seen = set(), set()
    vless_links, hy2_links = [], []

    def add_vless(item: str):
        item = item.strip()
        if item and item not in vless_seen:
            vless_seen.add(item)
            vless_links.append(item)

    def add_hy2(item: str):
        item = item.strip()
        if item and item not in hy2_seen:
            hy2_seen.add(item)
            hy2_links.append(item)

    def scan(text: str):
        for m in VLESS_REGEX.findall(text): add_vless(m)
        for m in HY2_REGEX.findall(text): add_hy2(m)

    scan(raw_text)

    decoded = try_decode_base64(raw_text)
    if decoded:
        scan(decoded)
        double_decoded = try_decode_base64(decoded)
        if double_decoded:
            scan(double_decoded)
        sb_v, sb_h = parse_singbox_json(decoded)
        for l in sb_v: add_vless(l)
        for l in sb_h: add_hy2(l)
        xr_v, xr_h = parse_xray_json(decoded)
        for l in xr_v: add_vless(l)
        for l in xr_h: add_hy2(l)

    sb_v, sb_h = parse_singbox_json(raw_text)
    for l in sb_v: add_vless(l)
    for l in sb_h: add_hy2(l)
    xr_v, xr_h = parse_xray_json(raw_text)
    for l in xr_v: add_vless(l)
    for l in xr_h: add_hy2(l)

    return vless_links, hy2_links

def decode_remark(link: str) -> str:
    if "#" in link:
        base, tag = link.split("#", 1)
        try:
            return f"{base}#{urllib.parse.unquote(tag)}"
        except Exception:
            return link
    return link

def get_remark(link: str) -> str:
    if "#" in link:
        _, tag = link.split("#", 1)
        try:
            return urllib.parse.unquote(tag)
        except Exception:
            return tag
    return "No remark"

def main():
    parser = argparse.ArgumentParser(description="Extract vless:// and hysteria2:// links from subscriptions and configs.")
    parser.add_argument("source", nargs="?", help="Subscription URL, file path, or raw string")
    parser.add_argument("-o", "--output", help="Output file to save links")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output with node remarks")
    parser.add_argument("-d", "--decode", action="store_true", help="Decode URL-encoded remarks in #fragment")
    parser.add_argument("-k", "--insecure", action="store_true", help="Skip SSL certificate validation")
    parser.add_argument("--hwid", help="Custom HWID identifier")
    parser.add_argument("--hy2", action="store_true", help="Include Hysteria 2 (hy2) links")
    parser.add_argument("--hy2-only", action="store_true", help="Extract only Hysteria 2 (hy2) links")
    parser.add_argument("--all", action="store_true", help="Extract all supported links (VLESS + Hysteria 2)")
    parser.add_argument("--pause", action="store_true", help="Wait for Enter before exiting")
    args = parser.parse_args()

    raw_input = args.source
    is_interactive = False

    if not raw_input:
        if not sys.stdin.isatty():
            raw_input = sys.stdin.read().strip()
        else:
            is_interactive = True
            print("==================================================")
            print("       VLESS & Hysteria 2 Extractor (Python)      ")
            print("==================================================")
            try:
                raw_input = input("Enter subscription URL or file path: ").strip()
                if not args.hwid:
                    hwid_in = input("Enter HWID (press Enter for auto): ").strip()
                    if hwid_in:
                        args.hwid = hwid_in
            except (KeyboardInterrupt, EOFError):
                sys.exit(0)

    if not raw_input:
        print("Error: No input provided.", file=sys.stderr)
        sys.exit(1)

    if raw_input.startswith("http://") or raw_input.startswith("https://"):
        print(f"[*] Fetching subscription: {raw_input} ...", file=sys.stderr)
        hwid = args.hwid or get_deterministic_hwid(raw_input)
        try:
            content = fetch_url(raw_input, hwid, args.insecure)
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            if is_interactive or args.pause:
                input("\nPress Enter to exit...")
            sys.exit(1)
    else:
        try:
            with open(raw_input, "r", encoding="utf-8") as f:
                print(f"[*] Reading file: {raw_input} ...", file=sys.stderr)
                content = f.read()
        except Exception:
            content = raw_input

    vless_links, hy2_links = extract_all_links(content)

    if args.hy2_only:
        selected_links = hy2_links
    elif args.hy2 or args.all:
        selected_links = vless_links + hy2_links
    else:
        if vless_links:
            selected_links = vless_links
            if hy2_links:
                print(f"[*] Note: {len(hy2_links)} Hysteria 2 link(s) also available (use --hy2 or --all to include).", file=sys.stderr)
        elif hy2_links:
            print(f"[*] No vless:// links found, displaying {len(hy2_links)} Hysteria 2 link(s):", file=sys.stderr)
            selected_links = hy2_links
        else:
            selected_links = []

    if not selected_links:
        print("[-] No supported proxy links found.", file=sys.stderr)
        if is_interactive or args.pause:
            input("\nPress Enter to exit...")
        sys.exit(1)

    print(f"[+] Total extracted links: {len(selected_links)}\n", file=sys.stderr)

    output_lines = []
    for i, link in enumerate(selected_links, 1):
        final_link = decode_remark(link) if args.decode else link
        output_lines.append(final_link)

        if args.verbose:
            remark = get_remark(link)
            print(f"[{i}] {remark}\n    {final_link}\n")
        else:
            print(final_link)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("\n".join(output_lines) + "\n")
            print(f"[+] Links saved to: {args.output}", file=sys.stderr)
        except Exception as e:
            print(f"[-] Error writing file: {e}", file=sys.stderr)

    if is_interactive or args.pause:
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
