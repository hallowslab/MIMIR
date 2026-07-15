from django.db import migrations


def create_geoip_update_schedule(apps, schema_editor):
    CrontabSchedule = apps.get_model("django_celery_beat", "CrontabSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = CrontabSchedule.objects.get_or_create(
        minute="0",
        hour="2",
        day_of_month="1",
        month_of_year="*",
    )
    PeriodicTask.objects.get_or_create(
        name="mimir-update-geoip-database",
        task="mimir.tasks.update_geoip_database",
        crontab=schedule,
        defaults={"queue": "mimir"},
    )


class Migration(migrations.Migration):

    dependencies = [
        ("mimir", "0002_securityalert_score_securityalert_severity"),
        ("django_celery_beat", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(create_geoip_update_schedule),
    ]
