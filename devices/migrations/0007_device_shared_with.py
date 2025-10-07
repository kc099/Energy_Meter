from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0006_alter_device_polling_interval'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='shared_with',
            field=models.ManyToManyField(
                blank=True,
                help_text='Users who can view this device in read-only mode',
                related_name='shared_devices',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
