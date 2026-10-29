# PHP2Shell — CVE-2026-109618 & CVE-2026-109619

**Pre-Authentication Remote Code Execution in PHP Core**

| | |
|---|---|
| **CVSS v4.0** | 9.2 (Critical) |
| **Affected** | PHP 5.4.0 – 8.5.11 (~78% websites globally) |
| **Patched** | PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+ |
| **Root Cause** | OOM `longjmp()` skips cleanup → stale Zend engine state → UAF → RCE |

Two critical vulnerabilities in PHP's `session.upload_progress` handler (RFC 1867) enable **pre-auth RCE** on default PHP installations. No application-level vulnerability required for some chains.

## CVEs

| CVE | Root Cause | SAPI | Impact |
|-----|-----------|------|--------|
| CVE-2026-109618 | OOM → `longjmp()` → stale `EG()` → UAF → RCE | Apache mod_php | Zero-dependency RCE |
| CVE-2026-109619 | Stale `BG(unserialize)` across FPM requests → UAF → RCE | PHP-FPM | Near-zero dependency RCE |

## Repository Structure

```
├── php2shell_report.md           # Full technical analysis (Vietnamese)
├── php2shell_chain_techniques.md # Technique mapping per chain (Vietnamese)
├── php2shell_check.py            # Non-destructive external scanner
├── php2shell_verify.py           # Scanner + exploit verifier (lab use)
├── chain_e_fpm_wfh.py            # Chain E PoC for PHP-FPM targets
└── raw.txt                       # Raw recon data
```

## Attack Chains

| Chain | Technique | Preconditions | SAPI | Complexity |
|-------|-----------|---------------|------|------------|
| **A** | Session injection + LFI → RCE | `upload_progress=On` (default) + LFI sink | Any | Low |
| **B** | `var_destroy` UAF → function handler overwrite → RCE | `unserialize()` with controlled data | Any | Medium |
| **C** | Session handler mismatch → `__destruct` → POP chain → RCE | FPM + mixed `serialize_handler` | FPM | Medium |
| **D** | OOM `longjmp` → stale `EG()` → UAF → heap spray → RCE | **None** (any PHP endpoint) | mod_php | High |
| **E** | Cross-request stale `BG()` → UAF → heap spray → RCE | `session_start()` endpoint | FPM | High |

### Technique Map

```
                    Code       Type        UAF     Heap    longjmp   Stale    Race
                  Injection  Confusion            Spray    Abuse    State   Condition

Chain A:            ██
Chain B:                                   ██      ██
Chain C:                       ██                                    ██
Chain D:                                   ██      ██       ██       ██
Chain E:                                   ██      ██       ██       ██       ██
```

## Quick Start

### Scanner (non-destructive, safe for production)

```bash
# Single target
python php2shell_check.py example.com

# With subdomain enumeration
python php2shell_check.py example.com --recon

# Batch scan
python php2shell_check.py -f targets.txt -o results.json
```

Detection methods:
1. **Version fingerprint** — headers, error pages, common paths
2. **Session upload_progress oracle** — 3 warnings = unpatched, 2 = patched
3. **OOM crash probe** — opt-in with `--crash` (may disrupt service)

### Verifier (lab use only)

```bash
# Scan + detect
python php2shell_verify.py scan http://target:8888

# Verify session injection primitives
python php2shell_verify.py verify http://target:8888

# Exploit Chain A (requires LFI sink)
python php2shell_verify.py exploit http://target:8888 --command "id"

# Full test suite
python php2shell_verify.py all http://target:8888
```

### Chain E — FPM Exploit

```bash
# Heap leak only
python chain_e_fpm_wfh.py --stage leak

# Full chain (requires PHP binary offsets)
python chain_e_fpm_wfh.py --stage full --cmd "id"
```

## Immediate Mitigation

```ini
; php.ini
session.upload_progress.enabled = Off
session.use_only_cookies = On
session.use_strict_mode = On
session.serialize_handler = php_serialize
```

> **Disabling `upload_progress` does NOT fix `var_destroy` UAF or serializer leak. Upgrading PHP is the only complete fix.**

### Patched Versions

| Branch | Fixed Version |
|--------|--------------|
| 8.2.x  | **8.2.35** |
| 8.3.x  | **8.3.36** |
| 8.4.x  | **8.4.27** |
| 8.5.x  | **8.5.12** |
| ≤ 8.1  | **EOL — no official fix** |

## Detection (WAF/IDS)

Block `PHP_SESSION_UPLOAD_PROGRESS` in multipart POST bodies:

```
# Suricata
alert http any any -> any any (msg:"PHP2SHELL upload_progress injection";
  flow:established,to_server; http.method; content:"POST";
  http.content_type; content:"multipart/form-data";
  file.data; content:"PHP_SESSION_UPLOAD_PROGRESS";
  classtype:web-application-attack; sid:2026001; rev:1;)
```

## References

- [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc) — Original PoC by Qi Deng
- [The Hacker News](https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html) — PHP Emergency Patches
- [Sansec Research](https://sansec.io/research/php2shell) — PHPSESSID heap leak
- [Bitdefender Advisory](https://www.bitdefender.com/en-us/blog/businessinsights/technical-advisory-php2shell-pre-auth-rce)
- [GHSA-w8hw-w9fx-j79w](https://github.com/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619

## Disclaimer

This repository is for **authorized security research and educational purposes only**. All tools are designed for use against systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.
