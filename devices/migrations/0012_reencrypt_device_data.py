from django.db import migrations


def reencrypt_payloads(apps, schema_editor):
    DeviceData = apps.get_model('devices', 'DeviceData')
    for entry in DeviceData.objects.iterator(chunk_size=500):
        value = entry.value
        if value in (None, ""):
            continue
        entry.__dict__['value'] = value
        entry.save(update_fields=['value'])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0011_encrypt_existing_device_data'),
    ]

    operations = [
        migrations.RunPython(reencrypt_payloads, noop),
    ]
