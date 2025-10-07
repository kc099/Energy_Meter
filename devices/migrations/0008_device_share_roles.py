from django.conf import settings
from django.db import migrations, models


def copy_existing_shares(apps, schema_editor):
    DeviceShare = apps.get_model('devices', 'DeviceShare')
    connection = schema_editor.connection
    introspection = connection.introspection
    existing_tables = set(introspection.table_names())
    legacy_table = 'devices_device_shared_with'

    if legacy_table not in existing_tables:
        return

    with connection.cursor() as cursor:
        cursor.execute(f'SELECT device_id, user_id FROM {legacy_table}')
        rows = cursor.fetchall()

    shares = [
        DeviceShare(device_id=device_id, user_id=user_id)
        for device_id, user_id in rows
    ]
    if shares:
        DeviceShare.objects.bulk_create(shares, ignore_conflicts=True)


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0007_device_shared_with'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='DeviceShare',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('role', models.CharField(choices=[('viewer', 'Data Viewer'), ('inspector', 'Configuration Viewer'), ('manager', 'Device Manager')], default='viewer', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('device', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='device_shares', to='devices.device')),
                ('user', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='device_shares', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'device_shares',
                'ordering': ['user__username'],
                'unique_together': {('device', 'user')},
            },
        ),
        migrations.RunPython(copy_existing_shares, migrations.RunPython.noop),
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    sql='DROP TABLE IF EXISTS devices_device_shared_with',
                    reverse_sql=migrations.RunSQL.noop,
                ),
            ],
            state_operations=[
                migrations.RemoveField(
                    model_name='device',
                    name='shared_with',
                ),
                migrations.AddField(
                    model_name='device',
                    name='shared_with',
                    field=models.ManyToManyField(blank=True, help_text='Users who have been granted access to this device', related_name='shared_devices', through='devices.DeviceShare', to=settings.AUTH_USER_MODEL),
                ),
            ],
        ),
    ]
