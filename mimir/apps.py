from django.apps import AppConfig


class MimirConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "mimir"
    verbose_name = "MIMIR"
    is_modular = True
    root_url = "/MIMIR"
    icon = "☁️"

    def get_dashboard_stats(self):

        total_rsync_jobs = 100
        total_rsync_job_failure_rate = 10.0
        total_transfer_tools = 12
        total_emails_created = 1024
        total_email_passwords_reset = 100

        return {
            "(WIP)Total Rsync Jobs": total_rsync_jobs,
            "(WIP)Total Rsync Job Failure Rate": f"{total_rsync_job_failure_rate:.1f}%",
            "(WIP)Total Transfer Tools": total_transfer_tools,
            "(WIP)Total Emails Created": total_emails_created,
            "(WIP)Total Email Passwords Reset": total_email_passwords_reset,
        }