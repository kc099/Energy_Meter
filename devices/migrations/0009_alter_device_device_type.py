from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0008_device_share_roles'),
    ]

    operations = [
        migrations.AlterField(
            model_name='device',
            name='device_type',
            field=models.CharField(
                choices=[
                    ('meter', 'Energy Meter'),
                    ('sensor', 'Sensor'),
                    ('monitor', 'Power Monitor'),
                    ('andon', 'Andon Station'),
                ],
                max_length=50,
            ),
        ),
    ]
