from django.urls import path

from . import views

app_name = "device-gateway"

urlpatterns = [
    # Preferred `/gateway/...` paths
    path("devices/<int:device_id>/provision", views.issue_provisioning_token_view, name="issue-token"),
    path("devices/claim", views.claim_device_view, name="claim-device"),
    path("device-data/ingest", views.telemetry_ingest_view, name="telemetry-ingest"),
    path("device-data/ingest-test", views.telemetry_ingest_test_view, name="telemetry-ingest-test"),
    path("devices/<int:device_id>/telemetry/latest", views.device_latest_payload_view, name="latest-telemetry"),
    path("device-tokens", views.device_token_management_view, name="token-management"),
    # Compatibility aliases matching firmware defaults (`/api/...`)
    path("api/devices/<int:device_id>/provision", views.issue_provisioning_token_view),
    path("api/devices/claim", views.claim_device_view),
    path("api/device-data/ingest", views.telemetry_ingest_view),
    path("api/device-data/ingest-test", views.telemetry_ingest_test_view),
    path("api/devices/<int:device_id>/telemetry/latest", views.device_latest_payload_view),
    path("api/device-tokens", views.device_token_management_view),
]
