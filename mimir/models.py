import uuid
import secrets
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django.db import models


class TargetServer(models.Model):
    name = models.CharField(max_length=255, unique=True)
    hostname = models.CharField(max_length=255)
    ssh_port = models.PositiveSmallIntegerField(default=22)
    log_file_path = models.CharField(max_length=512, help_text="e.g. /var/log/nginx/access.log")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name




class MimirJob(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending Upload"
        PROCESSING = "PROCESSING", "Analyzing Log"
        SUCCESS = "SUCCESS", "Analysis Complete"
        FAILED = "FAILED", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    server = models.ForeignKey(TargetServer, on_delete=models.CASCADE, null=True, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    temp_auth_token = models.CharField(max_length=255, unique=True)
    local_log_path = models.CharField(max_length=512, blank=True, null=True)
    report_html_path = models.CharField(max_length=512, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    error_message = models.TextField(blank=True, null=True)

    LOG_FORMAT_CHOICES = [
        ("COMBINED", "Combined (Nginx/Apache)"),
        ("COMMON", "Common (Apache)"),
    ]
    log_format = models.CharField(
        max_length=20, choices=LOG_FORMAT_CHOICES, default="COMBINED"
    )

    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="mimir_jobs",
    )
    target_hostname = models.CharField(max_length=255)
    target_port = models.PositiveSmallIntegerField(default=22)
    target_username = models.CharField(max_length=255)
    target_log_path = models.CharField(max_length=512)
    proxy_username = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        if not self.temp_auth_token:
            self.temp_auth_token = secrets.token_urlsafe(48)
        super().save(*args, **kwargs)

    def __str__(self):
        label = self.target_hostname or (self.server.name if self.server else "?")
        return f"Job {self.id} for {label}"

    @property
    def is_token_expired(self):
        ttl = getattr(settings, "MIMIR_TOKEN_TTL_MINUTES", 15)
        return timezone.now() > self.created_at + timedelta(minutes=ttl)


class SecurityAlert(models.Model):
    job = models.ForeignKey(MimirJob, on_delete=models.CASCADE, related_name='alerts')
    source_ip = models.GenericIPAddressField()
    scenario = models.CharField(max_length=255)
    description = models.TextField()
    detected_at = models.DateTimeField()

    def __str__(self):
        return f"Alert {self.scenario} from {self.source_ip}"
