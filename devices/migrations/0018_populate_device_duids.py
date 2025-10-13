from django.db import migrations
import uuid


def populate_duids(apps, schema_editor):
    Device = apps.get_model('devices', 'Device')
    for device in Device.objects.all():
        if not device.duid:
            device.duid = uuid.uuid4()
            device.save()


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0017_device_duid'),
    ]

    operations = [
        migrations.RunPython(populate_duids, migrations.RunPython.noop),
    ]
