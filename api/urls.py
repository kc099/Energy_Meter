from django.urls import path

from . import views

app_name = "api"

urlpatterns = [
    path("auth/session", views.session_view, name="auth-session"),
    path("auth/login", views.login_view, name="auth-login"),
    path("auth/logout", views.logout_view, name="auth-logout"),
    path("auth/register", views.register_view, name="auth-register"),
    path("auth/forgot-password", views.forgot_password_view, name="auth-forgot"),
    path("auth/reset-password", views.reset_password_view, name="auth-reset"),
    path("dashboard/overview", views.dashboard_overview_view, name="dashboard-overview"),
    path("devices", views.devices_view, name="devices"),
    path("devices/<int:device_id>", views.device_detail_view, name="device-detail"),
    path("devices/<int:device_id>/poll", views.device_poll_view, name="device-poll"),
    path("shifts", views.shifts_view, name="shifts"),
    path("shifts/<int:shift_id>", views.shift_detail_view, name="shift-detail"),
    path("shifts/<int:shift_id>/toggle", views.shift_toggle_view, name="shift-toggle"),
    path("shifts/reports", views.shift_reports_view, name="shift-reports"),
    path("shifts/reports/generate", views.shift_reports_generate_view, name="shift-reports-generate"),
]
