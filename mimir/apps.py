from django.apps import AppConfig
from django.utils.safestring import mark_safe


class MimirConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "mimir"
    verbose_name = "MIMIR"
    is_modular = True
    root_url = "/MIMIR"
    icon = mark_safe(
        '<img src="/static/mimir/MIMIR_NOBG.png" alt="MIMIR" style="height:1.2em; vertical-align:middle;">'
    )

    def get_dashboard_stats(self):
        from .models import MimirJob
        total = MimirJob.objects.count()
        success = MimirJob.objects.filter(status="SUCCESS").count()
        failed = MimirJob.objects.filter(status="FAILED").count()
        return {
            "Total Jobs": total,
            "Successful": success,
            "Failed": failed,
        }
