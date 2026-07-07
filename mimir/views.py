import os

import shutil

from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.http import require_POST

from .conf import MIMIR_PROXY_HOST
from .models import MimirJob
from .tasks import analyze_log_file
from .utils import (
    validate_job_token,
    safe_log_path,
    build_scp_download_linux,
    build_scp_download_windows,
    build_upload_curl,
    build_upload_curl_powershell,
)


@login_required
def index(request):
    jobs = MimirJob.objects.filter(requested_by=request.user).order_by("-created_at")
    return render(request, "mimir/index.html", {"jobs": jobs})


@login_required
def job_create(request):
    if request.method == "POST":
        job = MimirJob.objects.create(
            requested_by=request.user,
            target_hostname=request.POST["target_hostname"],
            target_port=int(request.POST.get("target_port", 22)),
            target_username=request.POST["target_username"],
            target_log_path=request.POST["target_log_path"],
            proxy_username=request.POST["proxy_username"],
            log_format=request.POST.get("log_format", "COMBINED"),
        )
        return redirect("mimir:job_detail", job_id=job.id)

    return render(request, "mimir/job_create.html")


@login_required
def job_detail(request, job_id):
    job = get_object_or_404(MimirJob, id=job_id, requested_by=request.user)
    proxy_host = MIMIR_PROXY_HOST
    ctx = {
        "job": job,
        "cmd_download_linux": build_scp_download_linux(job, job.proxy_username, proxy_host),
        "cmd_download_windows": build_scp_download_windows(job, job.proxy_username, proxy_host),
        "cmd_upload_curl": build_upload_curl(job),
        "cmd_upload_powershell": build_upload_curl_powershell(job),
        "proxy_host": proxy_host,
    }
    return render(request, "mimir/job_detail.html", ctx)


@staff_member_required
@require_POST
def job_delete(request, job_id):
    job = get_object_or_404(MimirJob, id=job_id)

    if job.local_log_path and os.path.isfile(job.local_log_path):
        os.remove(job.local_log_path)
    if job.report_html_path:
        report_dir = os.path.dirname(job.report_html_path)
        if os.path.isdir(report_dir):
            shutil.rmtree(report_dir, ignore_errors=True)

    job.alerts.all().delete()
    job.delete()
    return redirect("mimir:index")


@login_required
def job_status_api(request, job_id):
    job = get_object_or_404(MimirJob, id=job_id, requested_by=request.user)
    data = {
        "id": str(job.id),
        "status": job.status,
        "error_message": job.error_message,
        "created_at": job.created_at.isoformat(),
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "report_url": None,
    }
    if job.status == MimirJob.Status.SUCCESS and job.report_html_path:
        data["report_url"] = f"/MIMIR/reports/{job.id}/"
    return JsonResponse(data)


@csrf_exempt
@require_POST
def job_upload(request, job_id):
    job = get_object_or_404(MimirJob, id=job_id)

    auth = request.META.get("HTTP_AUTHORIZATION", "").removeprefix("Bearer ")
    if not validate_job_token(job, auth):
        return HttpResponseForbidden("Invalid or expired token")

    if "file" not in request.FILES:
        return HttpResponseBadRequest("No file uploaded")

    try:
        uploaded = request.FILES["file"]
        dest = safe_log_path(job.id)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as f:
            for chunk in uploaded.chunks():
                f.write(chunk)

        job.status = MimirJob.Status.PROCESSING
        job.local_log_path = dest
        job.save()

        analyze_log_file.delay(str(job.id))

        return JsonResponse({"status": "accepted", "job_id": str(job.id)})
    except Exception as e:
        job.status = MimirJob.Status.FAILED
        job.error_message = f"Upload failed: {e}"
        job.save()
        return JsonResponse({"error": str(e)}, status=500)


@login_required
@xframe_options_exempt
def report_view(request, job_id):
    job = get_object_or_404(MimirJob, id=job_id, requested_by=request.user)
    if job.status != MimirJob.Status.SUCCESS or not job.report_html_path:
        return redirect("mimir:job_detail", job_id=job.id)

    try:
        with open(job.report_html_path, "r") as f:
            html = f.read()
    except FileNotFoundError:
        return render(request, "mimir/report_not_found.html", {"job": job})

    return render(request, "mimir/report.html", {"job": job})


@login_required
def report_raw_view(request, job_id):
    job = get_object_or_404(MimirJob, id=job_id, requested_by=request.user)
    if job.status != MimirJob.Status.SUCCESS or not job.report_html_path:
        return redirect("mimir:job_detail", job_id=job.id)

    try:
        with open(job.report_html_path, "r") as f:
            html = f.read()
    except FileNotFoundError:
        return render(request, "mimir/report_not_found.html", {"job": job})

    return HttpResponse(html, content_type="text/html")


@login_required
def report_download(request, job_id):
    job = get_object_or_404(MimirJob, id=job_id, requested_by=request.user)
    if job.status != MimirJob.Status.SUCCESS or not job.report_html_path:
        return redirect("mimir:job_detail", job_id=job.id)

    try:
        with open(job.report_html_path, "r") as f:
            html = f.read()
    except FileNotFoundError:
        return render(request, "mimir/report_not_found.html", {"job": job})

    response = HttpResponse(html, content_type="text/html")
    response["Content-Disposition"] = f'attachment; filename="goaccess_report_{job.id}.html"'
    return response
