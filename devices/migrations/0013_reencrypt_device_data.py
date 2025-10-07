from django.db import migrations


def reencrypt_payloads(apps, schema_editor):
    DeviceData = apps.get_model('devices', 'DeviceData')
    qs = DeviceData.objects.order_by('pk')
    if hasattr(qs, 'iterator'):
        iterator = qs.iterator(chunk_size=500)
    else:
        iterator = qs
    for entry in iterator:
        value = entry.value
        if value in (None, ''):
            continue
        try:
            entry.__dict__['value'] = value
            entry.save(update_fields=['value'])
        except ValueError:
            continue


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0012_reencrypt_device_data'),
    ]

    operations = [
        migrations.RunPython(reencrypt_payloads, noop),
    ]
