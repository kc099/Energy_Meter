from django.urls import path
from . import views

app_name = "andon"
urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("stations/", views.station_list, name="station_list"),
    path("stations/<int:pk>/", views.station_detail, name="station_detail"),

    path("stations/add/", views.station_add, name="station_add"),
    path("stations/<int:pk>/edit/", views.station_edit, name="station_edit"),
    path("stations/<int:pk>/delete/", views.station_delete, name="station_delete"),
    path("api/stations/<int:pk>/telemetry/", views.telemetry_ingest_view, name="telemetry_ingest"),
]
