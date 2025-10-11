from django.urls import path

from . import views

app_name = "api_frontend"

urlpatterns = [
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("devices/", views.device_list_view, name="devices-list"),
    path("devices/<int:device_id>/", views.device_detail_view, name="devices-detail"),
    path("shifts/", views.manage_shifts_view, name="shifts"),
    path("shift-reports/", views.shift_reports_view, name="shift-reports"),
    path("bulk-share/", views.bulk_share_overview_view, name="bulk-share"),
    path("reports/preview/", views.reports_preview_view, name="reports-preview"),
]
