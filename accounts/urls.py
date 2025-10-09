from django.urls import path

from . import views


urlpatterns = [
    path("login/", views.LoginView, name="login"),
    path("register/", views.RegisterView, name="register"),
    path("logout/", views.logoutView, name="logout"),
    path("dashboard/", views.DashboardView, name="dashboard"),
    path("forgot-password/", views.ForgotPasswordView, name="forgot_password"),
    path("verify-reset-otp/", views.VerifyResetOTPView, name="verify_reset_otp"),
    path("change-password/", views.ChangePasswordView, name="change_password"),
    path("report-recipients/", views.ReportRecipientListView, name="report_recipients"),
    path(
        "report-recipients/<int:pk>/edit/",
        views.ReportRecipientUpdateView,
        name="report_recipient_edit",
    ),
    path(
        "report-recipients/<int:pk>/delete/",
        views.ReportRecipientDeleteView,
        name="report_recipient_delete",
    ),
]
