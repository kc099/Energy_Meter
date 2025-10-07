from django.urls import path
from . import views
urlpatterns = [
    path("login/", views.LoginView, name = "login"),
    path("register/", views.RegisterView, name = "register"),
    path("logout/", views.logoutView,name = "logout"),
    path("dashboard/", views.DashboardView, name = "dashboard"),
    path("forgotpassword/", views.ForgotPasswordView, name = "forgot_password"),
    path("resetpassword/", views.ResetPasswordView, name = "reset_password"),
    path("reset-password_validate/<uidb64>/<token>/", views.ResetpasswordView_validate, name = "reset_password" ),
]