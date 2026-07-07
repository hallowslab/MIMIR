import os
import re
from pathlib import Path

from .models import MimirJob
from .conf import (
    MIMIR_EXTERNAL_URL,
    MIMIR_INPUT_DIR,
    MIMIR_REPORT_DIR,
)


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