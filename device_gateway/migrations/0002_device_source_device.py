from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("devices", "0014_device_device_secret_deviceprovisioningtoken"),
        ("device_gateway", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="device",
            name="source_device",
            field=models.OneToOneField(
                blank=True,
                help_text="Link back to the primary devices.Device entry when available.",
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="gateway_device",
                to="devices.device",
            ),
        ),
    ]
