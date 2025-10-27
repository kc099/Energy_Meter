from django.urls import path

from . import views

app_name = "gas_monitor"

urlpatterns = [
    path("", views.device_list_view, name="device_list"),
    path("devices/add/", views.device_create_view, name="device_create"),
    path("devices/<int:pk>/", views.device_detail_view, name="device_detail"),
    path("devices/<int:pk>/edit/", views.device_update_view, name="device_update"),
    path("devices/<int:pk>/delete/", views.device_delete_view, name="device_delete"),
    path("api/devices/<int:pk>/telemetry/", views.telemetry_ingest_view, name="telemetry_ingest"),
]
