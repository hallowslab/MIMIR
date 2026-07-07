import os
import subprocess

from django.utils import timezone
from celery import shared_task

from .models import MimirJob, SecurityAlert
from .utils import safe_log_path, safe_report_path


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
        job.completed_at = timezone.now()
        job.status = "SUCCESS"
        job.save()

        # crowdsec_alerts = parse_crowdsec_alerts(log_path)
        # for alert_data in crowdsec_alerts:
        #     SecurityAlert.objects.create(
        #         job=job,
        #         source_ip=alert_data["ip"],
        #         scenario=alert_data["scenario"],
        #         description=alert_data["description"],
        #         detected_at=timezone.now(),
        #     )

    except Exception as e:
        job.status = "FAILED"
        job.error_message = str(e)
        job.completed_at = timezone.now()
        job.save()
        raise e
