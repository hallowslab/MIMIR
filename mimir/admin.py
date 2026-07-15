import hashlib
import os

from django.contrib import admin, messages
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import path
from django.utils.html import format_html

from .conf import MIMIR_GEOIP_DB_PATH, MIMIR_INPUT_DIR
from .log_generator import generate_log
from .models import TargetServer, MimirJob, SecurityAlert
from .tasks import analyze_log_file, update_geoip_database


@admin.register(TargetServer)
class TargetServerAdmin(admin.ModelAdmin):
    list_display = ("name", "hostname", "ssh_port", "log_file_path")
    search_fields = ("name", "hostname")


@admin.register(MimirJob)
class MimirJobAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "target_hostname",
        "status",
        "log_format",
        "requested_by",
        "created_at",
        "completed_at",
    )
    list_filter = ("status", "log_format", "created_at")
    search_fields = ("id", "target_hostname", "target_username")
    readonly_fields = (
        "id",
        "temp_auth_token",
        "created_at",
        "completed_at",
        "error_message",
    )
    change_list_template = "admin/mimir/mimirjob/mimirjob_changelist.html"

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                "generate-log/",
                self.admin_site.admin_view(self.generate_log_view),
                name="mimir_mimirjob_generate_log",
            ),
            path(
                "update-geoip/",
                self.admin_site.admin_view(self.update_geoip_view),
                name="mimir_mimirjob_update_geoip",
            ),
        ]
        return custom_urls + urls

    def generate_log_view(self, request):
        if request.method == "POST":
            lines = int(request.POST.get("lines", 1000))
            log_format = request.POST.get("log_format", "COMBINED")
            action = request.POST.get("action", "download")

            log_content = generate_log(lines=lines, log_format=log_format)

            if action == "download":
                response = HttpResponse(log_content, content_type="text/plain")
                response["Content-Disposition"] = (
                    f'attachment; filename="sample_{log_format.lower()}_{lines}.log"'
                )
                return response

            elif action == "analyze":
                from .utils import safe_log_path, safe_report_path

                job = MimirJob.objects.create(
                    requested_by=request.user,
                    target_hostname="sample-generator",
                    target_port=22,
                    target_username="admin",
                    target_log_path="internal://sample",
                    proxy_username="admin",
                    log_format=log_format,
                )

                log_path = safe_log_path(job.id)
                os.makedirs(os.path.dirname(log_path), exist_ok=True)
                with open(log_path, "w") as f:
                    f.write(log_content)

                job.local_log_path = log_path
                job.save()

                analyze_log_file.delay(str(job.id))

                self.message_user(
                    request,
                    f"Sample log generated and analysis started. Job #{job.id}",
                    messages.SUCCESS,
                )
                return HttpResponseRedirect(
                    f"../../mimirjob/{job.id}/change/"
                )

        context = {
            "title": "Generate Sample Log",
            "opts": self.model._meta,
        }
        return render(request, "admin/mimir/mimirjob/generate_log.html", context)

    def update_geoip_view(self, request):
        def get_db_info():
            info = {"path": MIMIR_GEOIP_DB_PATH, "exists": False}
            if os.path.exists(MIMIR_GEOIP_DB_PATH):
                stat = os.stat(MIMIR_GEOIP_DB_PATH)
                with open(MIMIR_GEOIP_DB_PATH, "rb") as f:
                    md5 = hashlib.md5(f.read()).hexdigest()
                info.update({
                    "exists": True,
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "md5": md5,
                })
            return info

        if request.method == "POST":
            old_info = get_db_info()

            try:
                result = update_geoip_database.delay()
                result.get(timeout=60)
                new_info = get_db_info()

                if not old_info["exists"]:
                    self.message_user(
                        request,
                        f"GeoIP database downloaded. MD5: {new_info.get('md5', 'N/A')}",
                        messages.SUCCESS,
                    )
                elif old_info.get("md5") == new_info.get("md5"):
                    self.message_user(
                        request,
                        f"GeoIP database unchanged (MD5: {new_info.get('md5', 'N/A')})",
                        messages.INFO,
                    )
                else:
                    self.message_user(
                        request,
                        f"GeoIP database updated. Old: {old_info.get('md5', 'N/A')} -> New: {new_info.get('md5', 'N/A')}",
                        messages.SUCCESS,
                    )
            except Exception as e:
                self.message_user(
                    request,
                    f"Failed to update GeoIP database: {e}",
                    messages.ERROR,
                )

            return HttpResponseRedirect("../")

        context = {
            "title": "Update GeoIP Database",
            "opts": self.model._meta,
            "db_info": get_db_info(),
        }
        return render(request, "admin/mimir/mimirjob/update_geoip.html", context)


@admin.register(SecurityAlert)
class SecurityAlertAdmin(admin.ModelAdmin):
    list_display = ("source_ip", "scenario", "severity", "score", "detected_at")
    list_filter = ("severity", "scenario", "detected_at")
    search_fields = ("source_ip", "scenario", "description")
    readonly_fields = ("job", "source_ip", "scenario", "description", "score", "detected_at")
