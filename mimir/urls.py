from django.urls import path
from . import views

app_name = "mimir"

urlpatterns = [
    path("", views.index, name="mimir_home"),
]
