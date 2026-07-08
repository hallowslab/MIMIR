import os
import subprocess

from django.utils import timezone
from celery import shared_task

from .models import MimirJob, SecurityAlert
from .utils import safe_log_path, safe_report_path, parse_security_events


@shared_task(bind=True)
def analyze_log_file(self, job_id):
    try:
        job = MimirJob.objects.get(id=job_id)
    except MimirJob.DoesNotExist:
        raise ValueError(f"Job with id {job_id} does not exist")

    try:
        job.status = "PROCESSING"
        job.save()

        log_path = safe_log_path(job.id)
        report_path = safe_report_path(job.id)

        os.makedirs(os.path.dirname(report_path), exist_ok=True)

        result = subprocess.run(
            ["goaccess", log_path, f"--log-format={job.log_format}", f"--output={report_path}"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"GoAccess failed (format: {job.log_format}). "
                f"stderr: {result.stderr.strip() or '(empty)'}"
            )

        job.report_html_path = report_path

        # ── Security event analysis ──────────────────────────
        with open(log_path, "r") as f:
            log_content = f.read()

        events = parse_security_events(log_content)
        for ev in events:
            SecurityAlert.objects.create(
                job=job,
                source_ip=ev["source_ip"],
                scenario=ev["scenario"],
                description=ev["description"],
                severity=ev["severity"],
                score=ev["score"],
                detected_at=timezone.now(),
            )

        job.completed_at = timezone.now()
        job.status = "SUCCESS"
        job.save()

    except Exception as e:
        job.status = "FAILED"
        job.error_message = str(e)
        job.completed_at = timezone.now()
        job.save()
        raise e
