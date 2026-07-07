from django.urls import path
from . import views

app_name = "mimir"

urlpatterns = [
    path("", views.index, name="index"),
    path("jobs/new/", views.job_create, name="job_create"),
    path("jobs/<uuid:job_id>/", views.job_detail, name="job_detail"),
    path("jobs/<uuid:job_id>/status/", views.job_status_api, name="job_status_api"),
    path("jobs/<uuid:job_id>/upload/", views.job_upload, name="job_upload"),
    path("reports/<uuid:job_id>/", views.report_view, name="report_view"),
    path("reports/<uuid:job_id>/raw/", views.report_raw_view, name="report_raw"),
    path("reports/<uuid:job_id>/download/", views.report_download, name="report_download"),
]
