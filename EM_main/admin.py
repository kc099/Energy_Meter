from django.contrib import admin
from ./andon/urls import urlpatterns
from django.urls import path, include

# EM_main/urls.py

urlpatterns += [
    path("admin/", admin.site.urls),
    path("accounts/", include("accounts.urls", namespace="accounts")),
    path("api/", include("api.urls", namespace="api")),
    path("devices/", include("devices.urls", namespace="devices")),
    path("andon/", include("andon.urls", namespace="andon")),
    path("gas_monitor/", include("gas_monitor.urls",  namespace="gas_monitor"))
]
