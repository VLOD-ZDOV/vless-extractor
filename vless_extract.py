#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VLESS Link Extractor
Extracts vless:// links from subscription URLs, Base64 strings, files,
and Sing-Box / Xray JSON configurations.
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
from typing import List

VLESS_REGEX = re.compile(r"vless://[^\s\"\'<>]+")

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
            if any(c in decoded_text for c in ("vless://", "vmess://", "trojan://", "ss://", "hysteria", "outbounds")):
                return decoded_text
        except Exception:
            continue
    return ""

def parse_xray_json(content: str) -> List[str]:
    links = []
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
                if not isinstance(ob, dict) or ob.get("protocol") != "vless":
                    continue
                tag = remarks or ob.get("tag", "")

                settings = ob.get("settings", {})
                vnext = settings.get("vnext", [])
                ss = ob.get("streamSettings", {})
                network = ss.get("network", "tcp")
                security = ss.get("security", "none")

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
                        if u.get("flow"):
                            params["flow"] = u.get("flow")
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
                        tag_enc = urllib.parse.quote(final_tag)
                        links.append(f"vless://{uuid}@{address}:{port}?{qs}#{tag_enc}")
    except Exception:
        pass
    return links

def parse_singbox_json(content: str) -> List[str]:
    links = []
    try:
        data = json.loads(content)
        outbounds = data.get("outbounds", [])
        if not isinstance(outbounds, list):
            return []

        for ob in outbounds:
            if not isinstance(ob, dict) or ob.get("type") != "vless":
                continue
            server = ob.get("server")
            uuid = ob.get("uuid")
            port = ob.get("server_port", 443)
            tag = ob.get("tag", server)
            if not server or server == "0.0.0.0" or not uuid or uuid == "00000000-0000-0000-0000-000000000000":
                continue

            query = {"encryption": "none"}
            if "flow" in ob and ob["flow"]:
                query["flow"] = ob["flow"]

            transport = ob.get("transport", {})
            net_type = transport.get("type", ob.get("network", "tcp"))
            query["type"] = net_type
            if "path" in transport:
                query["path"] = transport["path"]
            if "host" in transport:
                query["host"] = transport["host"]

            tls = ob.get("tls", {})
            if tls.get("enabled"):
                reality = tls.get("reality", {})
                if reality.get("enabled"):
                    query["security"] = "reality"
                    if "public_key" in reality:
                        query["pbk"] = reality["public_key"]
                    if "short_id" in reality:
                        query["sid"] = reality["short_id"]
                else:
                    query["security"] = "tls"

                if "server_name" in tls:
                    query["sni"] = tls["server_name"]
                utls = tls.get("utls", {})
                if utls.get("fingerprint"):
                    query["fp"] = utls["fingerprint"]
            else:
                query["security"] = "none"

            qs = urllib.parse.urlencode(query)
            tag_encoded = urllib.parse.quote(tag)
            links.append(f"vless://{uuid}@{server}:{port}?{qs}#{tag_encoded}")
    except Exception:
        pass
    return links

def extract_vless_links(raw_text: str) -> List[str]:
    found = []
    seen = set()

    def add(item: str):
        item = item.strip()
        if item and item not in seen:
            seen.add(item)
            found.append(item)

    for match in VLESS_REGEX.findall(raw_text):
        add(match)

    decoded = try_decode_base64(raw_text)
    if decoded:
        for match in VLESS_REGEX.findall(decoded):
            add(match)
        double_decoded = try_decode_base64(decoded)
        if double_decoded:
            for match in VLESS_REGEX.findall(double_decoded):
                add(match)
        for link in parse_singbox_json(decoded):
            add(link)
        for link in parse_xray_json(decoded):
            add(link)

    for link in parse_singbox_json(raw_text):
        add(link)
    for link in parse_xray_json(raw_text):
        add(link)

    return found

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
    parser = argparse.ArgumentParser(description="Extract vless:// links from subscriptions and configs.")
    parser.add_argument("source", nargs="?", help="Subscription URL, file path, or raw string")
    parser.add_argument("-o", "--output", help="Output file to save links")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output with node remarks")
    parser.add_argument("-d", "--decode", action="store_true", help="Decode URL-encoded remarks in #fragment")
    parser.add_argument("-k", "--insecure", action="store_true", help="Skip SSL certificate validation")
    parser.add_argument("--hwid", help="Custom HWID identifier")
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
            print("          VLESS Link Extractor (Python)           ")
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

    links = extract_vless_links(content)

    if not links:
        print("[-] No vless:// links found.", file=sys.stderr)
        if is_interactive or args.pause:
            input("\nPress Enter to exit...")
        sys.exit(1)

    print(f"[+] Found VLESS links: {len(links)}\n", file=sys.stderr)

    output_lines = []
    for i, link in enumerate(links, 1):
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
