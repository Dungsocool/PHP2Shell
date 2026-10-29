#!/usr/bin/env python3
"""
PHP2Shell Vulnerability Scanner - CVE-2026-109618 / CVE-2026-109619
Single-file, zero-dependency, non-destructive external scanner.

Detection:
  1. Subdomain recon via crt.sh Certificate Transparency
  2. PHP version fingerprint (headers + common paths + error pages)
  3. Session upload_progress oracle (3 warnings = unpatched)
  4. OOM crash probe (opt-in, --crash flag)

Fixed versions: 8.2.35, 8.3.36, 8.4.27, 8.5.12
EOL (no patch): PHP <= 8.1

Usage:
  python php2shell_check.py cmctelecom.vn
  python php2shell_check.py cmctelecom.vn --recon
  python php2shell_check.py cmctelecom.vn --recon --crash
  python php2shell_check.py -f targets.txt -o results.json
  python php2shell_check.py 192.168.1.10 -p 80,443,8080

Sources:
  https://research.jfrog.com/post/php2shell
  https://php2shell.aikido.io
  https://github.com/ikow/php2shell-poc
  https://github.com/zarguell/php2shell-scanner
  https://github.com/alanh0vx/php2shell-check
"""

import argparse
import json
import re
import socket
import ssl
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
# Version table
# ═══════════════════════════════════════════════════════════════

FIXED = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}


def parse_ver(s):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", s)
    return tuple(int(x) for x in m.groups()) if m else None


def judge_version(ver_str):
    v = parse_ver(ver_str)
    if not v:
        return "UNKNOWN", "Cannot parse"
    branch = (v[0], v[1])
    if branch in FIXED:
        if v < FIXED[branch]:
            fix = ".".join(map(str, FIXED[branch]))
            return "LIKELY_VULNERABLE", f"PHP {ver_str} < {fix}"
        return "PATCHED", f"PHP {ver_str} >= {'.'.join(map(str, FIXED[branch]))}"
    if v[0] < 8 or (v[0] == 8 and v[1] <= 1):
        return "EOL_NO_PATCH", f"PHP {ver_str} — EOL, no official fix"
    return "UNKNOWN", f"PHP {ver_str} — unknown branch"


# ═══════════════════════════════════════════════════════════════
# HTTP
# ═══════════════════════════════════════════════════════════════

_SSL_CTX = None


def ssl_ctx():
    global _SSL_CTX
    if not _SSL_CTX:
        _SSL_CTX = ssl.create_default_context()
        _SSL_CTX.check_hostname = False
        _SSL_CTX.verify_mode = ssl.CERT_NONE
    return _SSL_CTX


def http(url, method="GET", data=None, headers=None, timeout=6):
    h = {"User-Agent": "PHP2Shell-Check/1.0 (Security Audit)", "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, method=method, headers=h, data=data)
    ctx = ssl_ctx() if url.startswith("https") else None
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return r.status, dict(r.headers), r.read(65536)
    except urllib.error.HTTPError as e:
        hd = dict(e.headers) if hasattr(e, "headers") else {}
        try:
            bd = e.read(65536)
        except Exception:
            bd = b""
        return e.code, hd, bd
    except Exception:
        return None, {}, b""


def raw_tcp(host, port, data, tls=False, timeout=8):
    """Raw socket request — needed for chunked/malformed probes."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if tls:
            s = ssl_ctx().wrap_socket(s, server_hostname=host)
        s.sendall(data)
        s.settimeout(timeout)
        resp = b""
        while True:
            try:
                c = s.recv(65536)
                if not c:
                    break
                resp += c
            except (socket.timeout, ConnectionResetError, ssl.SSLError):
                break
        s.close()
        return resp
    except Exception:
        return b""


# ═══════════════════════════════════════════════════════════════
# Recon
# ═══════════════════════════════════════════════════════════════

def recon_crtsh(domain):
    """Enumerate subdomains via crt.sh Certificate Transparency."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    status, _, body = http(url, timeout=15)
    if status != 200 or not body:
        return []
    try:
        entries = json.loads(body)
    except Exception:
        return []
    subs = set()
    for e in entries:
        for line in e.get("name_value", "").split("\n"):
            line = line.strip().lstrip("*.").lower()
            if line and (line == domain or line.endswith("." + domain)):
                subs.add(line)
    return sorted(subs)


# ═══════════════════════════════════════════════════════════════
# Detection methods
# ═══════════════════════════════════════════════════════════════

def extract_php_ver(headers, body=b""):
    """Try to extract PHP version from response."""
    for h in ("X-Powered-By", "Server"):
        m = re.search(r"PHP/(\d+\.\d+\.\d+)", headers.get(h, ""))
        if m:
            return m.group(1), h
    if body:
        m = re.search(rb"PHP/(\d+\.\d+\.\d+)", body)
        if m:
            return m.group(1).decode(), "body"
        # phpinfo page
        m = re.search(rb"PHP Version\s*</td><td[^>]*>(\d+\.\d+\.\d+)", body)
        if m:
            return m.group(1).decode(), "phpinfo"
    return None, None


def detect_php(base_url, timeout=6):
    """
    Multi-path PHP detection.
    Returns (version, source, server_header, php_detected_bool)
    """
    paths = ["/", "/index.php", "/wp-login.php", "/administrator/",
             "/user/login", "/info.php", "/phpinfo.php", "/test.php"]

    for path in paths:
        url = base_url.rstrip("/") + path
        status, hdrs, body = http(url, timeout=timeout)
        if not status:
            continue

        ver, src = extract_php_ver(hdrs, body)
        srv = hdrs.get("Server", "")

        if ver:
            return ver, f"{src} @ {path}", srv, True

        # PHP indicators without version
        php_hints = (
            "PHPSESSID" in hdrs.get("Set-Cookie", "")
            or hdrs.get("X-Powered-By", "").startswith("PHP")
            or b"<?php" in (body or b"")
            or b"Fatal error" in (body or b"")
            or b"Parse error" in (body or b"")
        )
        if php_hints:
            return None, f"indicators @ {path}", srv, True

    # Check first successful response for server info
    status, hdrs, _ = http(base_url, timeout=timeout)
    return None, None, hdrs.get("Server", "") if status else "", bool(status)


def session_oracle(base_url, timeout=8):
    """
    Session-write oracle (zarguell method).
    POST multipart with PHP_SESSION_UPLOAD_PROGRESS + invalid session.
    Unpatched: 3 warnings (session write path). Patched: 2. Hidden: 0.
    """
    boundary = f"----Php2ShellOracle{int(time.time())}"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\noracle\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="t.txt"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\ntest\r\n"
        f"--{boundary}--\r\n"
    ).encode()

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Cookie": "PHPSESSID=php2shell_oracle_probe",
    }

    status, _, resp_body = http(base_url, method="POST", data=body,
                                 headers=headers, timeout=timeout)
    if not status:
        return "NO_RESPONSE", 0, "No HTTP response"

    if resp_body:
        warns = len(re.findall(rb"(?:Warning|Notice|Fatal error):", resp_body))
        has_session_warn = (b"session_write" in resp_body or
                           b"session_start" in resp_body or
                           b"upload_progress" in resp_body)
        if warns >= 3 and has_session_warn:
            return "VULNERABLE", warns, f"{warns} warnings incl. session_write (unpatched)"
        if warns >= 3:
            return "LIKELY_VULNERABLE", warns, f"{warns} warnings"
        if warns == 2:
            return "POSSIBLY_PATCHED", warns, f"2 warnings (patched signature?)"
        if warns > 0:
            return "WARNINGS", warns, f"{warns} warning(s)"
        if b"Allowed memory size" in resp_body:
            return "OOM_DETECTED", 0, "Memory exhaustion in response"

    if status == 403:
        return "BLOCKED", 0, "403 — WAF/firewall"
    if status == 405:
        return "BLOCKED", 0, "405 — Method Not Allowed"
    if status >= 500:
        return "SERVER_ERROR", 0, f"HTTP {status}"

    return "HIDDEN", 0, f"HTTP {status} — display_errors likely Off"


def crash_probe(host, port, path="/", tls=False, sizes=(1, 8, 20)):
    """
    OOM crash probe (Aikido/alanh0vx method).
    Sends large multipart via raw socket. Checks for worker crash.
    WARNING: May disrupt service.
    """
    for size_mb in sizes:
        boundary = f"----Php2ShellCrash{int(time.time())}"
        progress = b"A" * 4096
        payload = b"X" * (size_mb * 1024 * 1024)
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        ).encode() + progress + (
            f"\r\n--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f"; filename="c.bin"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()

        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Cookie: PHPSESSID=crash_probe\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body

        resp = raw_tcp(host, port, req, tls=tls, timeout=15)

        if not resp:
            return "LIKELY_CRASH", size_mb, f"No response with {size_mb}MB — worker may have died"
        if b"Fatal error" in resp and b"memory" in resp.lower():
            return "OOM_CONFIRMED", size_mb, f"Fatal OOM error with {size_mb}MB"
        if b"Allowed memory size" in resp:
            return "OOM_CONFIRMED", size_mb, f"Memory exhaustion with {size_mb}MB"
        status_line = resp.split(b"\r\n", 1)[0]
        if b"500" in status_line:
            return "HTTP_500", size_mb, f"HTTP 500 with {size_mb}MB"
        if b"502" in status_line:
            return "FPM_CRASH", size_mb, f"HTTP 502 (FPM worker crash) with {size_mb}MB"

    return "NOT_TRIGGERED", sizes[-1], "No crash detected — memory_limit may be high or WAF blocked"


# ═══════════════════════════════════════════════════════════════
# Scanner core
# ═══════════════════════════════════════════════════════════════

def scan_one(domain, ports=(443, 80, 8080, 8443), do_crash=False, timeout=6):
    """Full scan of a single domain. Returns result dict."""
    r = {
        "domain": domain,
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": None,
        "reachable": False,
        "server": "",
        "php_detected": False,
        "php_version": None,
        "ver_source": None,
        "ver_verdict": None,
        "ver_detail": None,
        "oracle_verdict": None,
        "oracle_detail": None,
        "crash_verdict": None,
        "crash_detail": None,
        "verdict": "UNKNOWN",
        "confidence": "NONE",
        "note": "",
    }

    # DNS
    try:
        socket.setdefaulttimeout(3)
        r["ip"] = socket.getaddrinfo(domain, 443)[0][4][0]
    except socket.gaierror:
        r["verdict"] = "DNS_FAIL"
        r["note"] = "Domain does not resolve"
        return r

    # Try ports
    for port in ports:
        tls = port in (443, 8443)
        scheme = "https" if tls else "http"
        base = f"{scheme}://{domain}" if port in (80, 443) else f"{scheme}://{domain}:{port}"

        ver, src, srv, php = detect_php(base, timeout=timeout)
        if not srv and not php:
            continue  # Port not responding

        r["reachable"] = True
        r["server"] = srv

        if ver:
            r["php_detected"] = True
            r["php_version"] = ver
            r["ver_source"] = src
            vv, vd = judge_version(ver)
            r["ver_verdict"] = vv
            r["ver_detail"] = vd
        elif php:
            r["php_detected"] = True
            r["ver_source"] = src

        # Session oracle
        ov, _, od = session_oracle(base, timeout=timeout)
        r["oracle_verdict"] = ov
        r["oracle_detail"] = od

        # Crash probe (opt-in)
        if do_crash and r["php_detected"]:
            cv, _, cd = crash_probe(domain, port, "/", tls=tls)
            r["crash_verdict"] = cv
            r["crash_detail"] = cd

        if r["php_detected"]:
            break  # Found PHP, no need for other ports

    if not r["reachable"]:
        r["verdict"] = "UNREACHABLE"
        r["note"] = "DNS ok but no HTTP response on any port"
        return r

    # Overall verdict
    signals = [r["ver_verdict"], r["oracle_verdict"], r["crash_verdict"]]
    if any(s in ("VULNERABLE", "LIKELY_VULNERABLE") for s in signals):
        r["verdict"] = "VULNERABLE"
        r["confidence"] = "HIGH"
    elif r["ver_verdict"] == "EOL_NO_PATCH":
        r["verdict"] = "EOL_VULNERABLE"
        r["confidence"] = "MEDIUM"
    elif any(s in ("OOM_CONFIRMED", "LIKELY_CRASH", "FPM_CRASH") for s in signals):
        r["verdict"] = "LIKELY_VULNERABLE"
        r["confidence"] = "MEDIUM"
    elif r["ver_verdict"] == "PATCHED":
        r["verdict"] = "PATCHED"
        r["confidence"] = "HIGH"
    elif r["ver_verdict"] in ("LIKELY_VULNERABLE",):
        r["verdict"] = "LIKELY_VULNERABLE"
        r["confidence"] = "MEDIUM"
    elif any(s == "BLOCKED" for s in signals):
        r["verdict"] = "BLOCKED"
        r["confidence"] = "LOW"
        r["note"] = "WAF/CDN blocking probes"
    elif r["php_detected"]:
        r["verdict"] = "INCONCLUSIVE"
        r["confidence"] = "LOW"
        r["note"] = "PHP detected but version hidden"
    else:
        r["verdict"] = "NO_PHP"
        r["confidence"] = "LOW"
        r["note"] = f"Server: {r['server']}"

    return r


# ═══════════════════════════════════════════════════════════════
# Output
# ═══════════════════════════════════════════════════════════════

RED = "\033[91m"
YEL = "\033[93m"
GRN = "\033[92m"
CYN = "\033[96m"
BLD = "\033[1m"
DIM = "\033[2m"
RST = "\033[0m"

VCOLORS = {
    "VULNERABLE": RED, "LIKELY_VULNERABLE": RED, "EOL_VULNERABLE": RED,
    "INCONCLUSIVE": YEL, "BLOCKED": YEL,
    "PATCHED": GRN, "NO_PHP": DIM, "UNREACHABLE": DIM, "DNS_FAIL": DIM,
}


def print_line(r):
    c = VCOLORS.get(r["verdict"], RST)
    ver = r["php_version"] or "-"
    ip = r["ip"] or "-"
    extra = ""
    if r["ver_detail"]:
        extra = r["ver_detail"]
    elif r["oracle_detail"]:
        extra = f"oracle: {r['oracle_detail']}"
    elif r["note"]:
        extra = r["note"]
    elif r["server"]:
        extra = f"Server: {r['server']}"

    print(
        f"  {c}{r['verdict']:22s}{RST} "
        f"{r['domain']:45s} "
        f"{ver:12s} "
        f"{ip:18s} "
        f"{DIM}{extra}{RST}",
        flush=True,
    )


def print_header():
    print(f"\n{BLD}  {'VERDICT':22s} {'DOMAIN':45s} {'PHP VER':12s} {'IP':18s} DETAIL{RST}")
    print(f"  {'-'*130}", flush=True)


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

def main():
    banner = (
        f"\n{BLD}================================================================\n"
        f"  PHP2Shell Scanner - CVE-2026-109618 / CVE-2026-109619\n"
        f"  Non-destructive external vulnerability checker\n"
        f"================================================================{RST}\n"
    )
    ap = argparse.ArgumentParser(
        description="PHP2Shell Scanner - CVE-2026-109618/109619",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s cmctelecom.vn                          Quick scan
  %(prog)s cmctelecom.vn --recon                   + subdomain enum
  %(prog)s cmctelecom.vn --recon --crash           + OOM crash test
  %(prog)s -f targets.txt -o results.json          Batch + JSON output
  %(prog)s 10.0.0.0/24 -p 80,443                  Internal scan
""",
    )
    ap.add_argument("targets", nargs="*", help="Domains or IPs to scan")
    ap.add_argument("-f", "--file", help="File with targets (one per line)")
    ap.add_argument("--recon", action="store_true", help="Enumerate subdomains via crt.sh")
    ap.add_argument("--crash", action="store_true", help="OOM crash probe (may disrupt!)")
    ap.add_argument("-p", "--ports", default="443,80,8080,8443")
    ap.add_argument("-t", "--timeout", type=int, default=6)
    ap.add_argument("-o", "--output", help="Save JSON results to file")
    ap.add_argument("--json", action="store_true", help="Print JSON to stdout")
    args = ap.parse_args()

    print(banner)

    # Collect targets
    targets = list(args.targets or [])
    if args.file:
        with open(args.file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    if not targets:
        ap.error("No targets. Pass domains as args or use -f file.")

    ports = [int(p) for p in args.ports.split(",")]

    # Clean & expand targets
    all_targets = []
    for t in targets:
        if "://" in t:
            from urllib.parse import urlparse
            t = urlparse(t).hostname
        t = t.strip("/").lower()
        all_targets.append(t)

        if args.recon:
            print(f"  {BLD}[recon]{RST} Enumerating subdomains for {t} via crt.sh...", flush=True)
            subs = recon_crtsh(t)
            # Filter out S3/storage endpoints
            subs = [s for s in subs if not s.startswith("s3") and "s3." not in s]
            if subs:
                print(f"  {BLD}[recon]{RST} Found {len(subs)} subdomains (excl. S3)", flush=True)
                for s in subs:
                    if s not in all_targets:
                        all_targets.append(s)
            else:
                print(f"  {DIM}[recon] No subdomains found{RST}", flush=True)

    all_targets = list(dict.fromkeys(all_targets))  # dedup

    print(f"\n  Scanning {BLD}{len(all_targets)}{RST} target(s) on ports {ports}")
    if args.crash:
        print(f"  {RED}[!] OOM CRASH PROBE ENABLED — may disrupt PHP workers{RST}")
    print_header()

    # Scan
    results = []
    for t in all_targets:
        r = scan_one(t, ports=ports, do_crash=args.crash, timeout=args.timeout)
        results.append(r)
        print_line(r)

    # Sort by severity
    sev = {"VULNERABLE": 0, "LIKELY_VULNERABLE": 1, "EOL_VULNERABLE": 2,
           "INCONCLUSIVE": 3, "BLOCKED": 4, "PATCHED": 5,
           "NO_PHP": 6, "UNREACHABLE": 7, "DNS_FAIL": 8, "UNKNOWN": 9}
    results.sort(key=lambda x: sev.get(x["verdict"], 99))

    # Summary
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1

    print(f"\n{BLD}  ══ SUMMARY ══{RST}")
    for v in sorted(counts, key=lambda x: sev.get(x, 99)):
        c = VCOLORS.get(v, RST)
        print(f"  {c}{v:22s}{RST}  {counts[v]}")
    print(f"  {'TOTAL':22s}  {len(results)}")

    vuln_count = sum(1 for r in results if r["verdict"] in
                     ("VULNERABLE", "LIKELY_VULNERABLE", "EOL_VULNERABLE"))
    if vuln_count:
        print(f"\n  {RED}{BLD}⚠  {vuln_count} target(s) need immediate attention!{RST}")
    else:
        print(f"\n  {GRN}✓  No exposed PHP vulnerabilities detected from external scan.{RST}")
        print(f"  {DIM}  Note: PHP may run behind reverse proxy with hidden version.{RST}")
        print(f"  {DIM}  Recommend: internal scan with direct server access.{RST}")

    # Output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n  Results saved: {args.output}")

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))

    print()
    sys.exit(2 if vuln_count else 0)


if __name__ == "__main__":
    main()
