from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Device",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=100)),
                ("location", models.CharField(blank=True, max_length=200)),
                ("latest_payload", models.JSONField(blank=True, null=True)),
                ("last_seen", models.DateTimeField(blank=True, null=True)),
                (
                    "device_secret",
                    models.CharField(
                        blank=True,
                        help_text="Last issued device credential in plain text (optional).",
                        max_length=128,
                        null=True,
                    ),
                ),
                (
                    "device_secret_hash",
                    models.CharField(
                        blank=True,
                        editable=False,
                        help_text="SHA-256 hash of the active device credential.",
                        max_length=64,
                        null=True,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "owner",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="gateway_devices",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="DeviceProvisioningToken",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("token_hash", models.CharField(max_length=64, unique=True)),
                ("expires_at", models.DateTimeField()),
                ("used_at", models.DateTimeField(blank=True, null=True)),
                ("metadata", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "device",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="provisioning_tokens",
                        to="device_gateway.device",
                    ),
                ),
                (
                    "issued_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="issued_gateway_tokens",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="DeviceTelemetry",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("payload", models.JSONField()),
                ("received_at", models.DateTimeField(auto_now_add=True)),
                (
                    "device",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="telemetry",
                        to="device_gateway.device",
                    ),
                ),
            ],
            options={
                "ordering": ["-received_at"],
            },
        ),
        migrations.AddIndex(
            model_name="device",
            index=models.Index(fields=["owner", "created_at"], name="device_owner_created_idx"),
        ),
        migrations.AddIndex(
            model_name="deviceprovisioningtoken",
            index=models.Index(fields=["device", "expires_at"], name="token_device_expiry_idx"),
        ),
        migrations.AddIndex(
            model_name="devicetelemetry",
            index=models.Index(fields=["device", "-received_at"], name="telemetry_device_latest_idx"),
        ),
    ]
