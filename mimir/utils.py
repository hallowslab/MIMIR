import logging
import os
import re
from pathlib import Path

from .models import MimirJob
from .conf import (
    MIMIR_EXTERNAL_URL,
    MIMIR_INPUT_DIR,
    MIMIR_REPORT_DIR,
)

logger = logging.getLogger("mimir.utils")

def validate_job_token(job, token):
    if job.temp_auth_token != token:
        return False
    if job.status != MimirJob.Status.PENDING:
        return False
    if job.is_token_expired:
        return False
    return True


def safe_log_path(job_id):
    raw = os.path.join(MIMIR_INPUT_DIR, f"job_{job_id}.log")
    resolved = Path(raw).resolve()
    allowed = Path(MIMIR_INPUT_DIR).resolve()
    if not str(resolved).startswith(str(allowed)):
        raise ValueError("Path traversal detected")
    return str(resolved)


def safe_report_path(job_id):
    raw = os.path.join(MIMIR_REPORT_DIR, str(job_id), "index.html")
    resolved = Path(raw).resolve()
    allowed = Path(MIMIR_REPORT_DIR).resolve()
    if not str(resolved).startswith(str(allowed)):
        raise ValueError("Path traversal detected")
    return str(resolved)


def build_scp_download_linux(job, proxy_user, proxy_host):
    return (
        f"scp -o StrictHostKeyChecking=no "
        f"-J {proxy_user}@{proxy_host} "
        f"{job.target_username}@{job.target_hostname}:{job.target_log_path} "
        f"./job_{job.id}.log"
    )


def build_scp_download_windows(job, proxy_user, proxy_host):
    return (
        f'scp -o StrictHostKeyChecking=no '
        f'-o ProxyJump={proxy_user}@{proxy_host} '
        f'{job.target_username}@{job.target_hostname}:{job.target_log_path} '
        f'./job_{job.id}.log'
    )


def build_upload_curl(job):
    return (
        f'curl -X POST '
        f'{MIMIR_EXTERNAL_URL}/MIMIR/jobs/{job.id}/upload/ '
        f'-F "file=@./job_{job.id}.log" '
        f'-H "Authorization: Bearer {job.temp_auth_token}"'
    )


def build_upload_curl_powershell(job):
    return (
        f'curl.exe -X POST '
        f'{MIMIR_EXTERNAL_URL}/MIMIR/jobs/{job.id}/upload/ '
        f'-F "file=@./job_{job.id}.log" '
        f'-H "Authorization: Bearer {job.temp_auth_token}"'
    )


# ── Combined Log Format regex ──────────────────────────────────
COMBINED_RE = re.compile(
    r'^(\S+)'                      # IP
    r'\s+\S+'                      # ident
    r'\s+\S+'                      # authuser
    r'\s+\[([^\]]+)\]'             # date
    r'\s+"(\S+)\s+(\S+)\s+\S+"'   # method, path
    r'\s+(\d{3})'                  # status
    r'\s+(\d+|-)'                  # size
    r'\s+"([^"]*)"'                # referer
    r'\s+"([^"]*)"'                # user-agent
)


def parse_security_events(log_content):
    """Analyze a parsed log line and return a list of SecurityAlert-like dicts."""
    from collections import Counter, defaultdict

    lines = []
    for raw_line in log_content.splitlines():
        m = COMBINED_RE.match(raw_line)
        if not m:
            continue
        lines.append({
            "ip": m.group(1),
            "time": m.group(2),
            "method": m.group(3),
            "path": m.group(4),
            "status": int(m.group(5)),
            "referer": m.group(7),
            "ua": m.group(8),
        })

    if not lines:
        return []

    # Per-IP counters
    ip_count = Counter(l["ip"] for l in lines)
    ip_401 = Counter(l["ip"] for l in lines if l["status"] == 401)
    ip_403 = Counter(l["ip"] for l in lines if l["status"] == 403)
    ip_404 = Counter(l["ip"] for l in lines if l["status"] == 404)

    # Group paths by IP
    ip_paths = defaultdict(list)
    for l in lines:
        ip_paths[l["ip"]].append(l["path"])

    # ── Score each IP ──────────────────────────────────────────
    SEVERITY_THRESHOLDS = [(30, "CRITICAL"), (15, "HIGH"), (5, "MEDIUM")]
    sql_re = re.compile(r"(%27|'|--|union\s+select|insert\s+into|drop\s+table|exec\s+\()",
                        re.I)
    xss_re = re.compile(r"(<script|alert\s*\(|onerror\s*=|onload\s*=|javascript:)",
                        re.I)
    traversal_re = re.compile(r"(\.\./|\.\.\\|%2e%2e|%2E%2E|\./\./)", re.I)
    cmd_inj_re = re.compile(r"(;\s*cat\s|;\s*rm\s|;\s*whoami|`[^`]+`|\$\(|%00)", re.I)
    sensitive_re = re.compile(
        r"(/etc/passwd|/etc/shadow|/\.env|wp-config|\.git/config|\.aws/credentials)",
        re.I
    )

    scanner_uas = {
        "sqlmap", "nikto", "nmap", "nessus", "openvas", "acunetix",
        "wpscan", "dirbuster", "gobuster", "hydra", "medusa",
        "masscan", "zmap", "burp", "python-requests", "go-http-client",
        "zgrab", "cve-", "metasploit",
    }

    results = []
    for ip, total_reqs in ip_count.most_common():
        score = 0.0
        alerts = []  # (scenario, description)

        # ── Authentication failures ────────────────────────
        n401 = ip_401.get(ip, 0)
        n403 = ip_403.get(ip, 0)
        n404 = ip_404.get(ip, 0)

        if n401 >= 3:
            a_score = n401 * 1.0
            score += a_score
            alerts.append((
                "BRUTE_FORCE_401",
                f"{n401}x HTTP 401 from {ip} — possible brute-force / credential stuffing"
            ))

        if n403 >= 3:
            a_score = n403 * 1.5
            score += a_score
            alerts.append((
                "BRUTE_FORCE_403",
                f"{n403}x HTTP 403 from {ip} — possible forced-browsing / auth bypass attempts"
            ))

        if n404 >= 20:
            a_score = (n404 / total_reqs) * 10
            score += a_score
            alerts.append((
                "PATH_SCANNING",
                f"{n404}x HTTP 404 from {ip} ({n404/total_reqs*100:.0f}% of requests) — directory/endpoint brute-force"
            ))

        # ── Injection attempts ─────────────────────────────
        for l in lines:
            if l["ip"] != ip:
                continue
            path = l["path"]
            ua = l["ua"]

            if sql_re.search(path):
                score += 8
                alerts.append(("SQL_INJECTION", f"SQLi pattern in path: {path}"))

            if xss_re.search(path):
                score += 6
                alerts.append(("XSS_ATTEMPT", f"XSS pattern in path: {path}"))

            if traversal_re.search(path):
                score += 7
                alerts.append(("PATH_TRAVERSAL", f"Path traversal in path: {path}"))

            if cmd_inj_re.search(path):
                score += 8
                alerts.append(("CMD_INJECTION", f"Command injection pattern in path: {path}"))

            if sensitive_re.search(path):
                score += 7
                alerts.append(("SENSITIVE_FILE_ACCESS", f"Sensitive file access: {path}"))

            # ── Scanner User-Agent ────────────────────────
            ua_lower = ua.lower()
            matched_scanner = next((s for s in scanner_uas if s in ua_lower), None)
            if matched_scanner:
                score += 5
                alerts.append((
                    "SCANNER_DETECTED",
                    f"Scanner User-Agent detected: {ua[:100]}"
                ))

        # ── Determine severity ─────────────────────────────
        severity = "LOW"
        for threshold, label in SEVERITY_THRESHOLDS:
            if score >= threshold:
                severity = label
                break

        # Only report IPs with meaningful activity
        if score > 0:
            combined_desc = "; ".join(f"{s}: {d}" for s, d in alerts[:5])
            if len(alerts) > 5:
                combined_desc += f" (+{len(alerts)-5} more)"
            results.append({
                "source_ip": ip,
                "score": round(score, 1),
                "severity": severity,
                "scenario": alerts[0][0] if alerts else "SUSPICIOUS_ACTIVITY",
                "description": combined_desc,
                "alert_count": len(alerts),
            })

    results.sort(key=lambda r: r["score"], reverse=True)
    logger.debug(f"Security event analysis results: {results}")
    return results


def validate_log_file(log_content):
    if not log_content:
        raise ValueError("Log content cannot be empty")
    suspicious_patterns = [
        r'root.*password',
        r'admin.*login',
        r'sudo.*password'
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, log_content, re.IGNORECASE):
            raise ValueError("Suspicious content detected in log file")
    return True