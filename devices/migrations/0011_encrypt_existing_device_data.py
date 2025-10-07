from django.db import migrations


def encrypt_existing_payloads(apps, schema_editor):
    DeviceData = apps.get_model('devices', 'DeviceData')
    for entry in DeviceData.objects.iterator(chunk_size=500):
        raw = entry.value
        if isinstance(raw, (dict, list)):
            entry.value = raw
            entry.save(update_fields=['value'])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0010_alter_devicedata_value'),
    ]

    operations = [
        migrations.RunPython(encrypt_existing_payloads, noop),
    ]
