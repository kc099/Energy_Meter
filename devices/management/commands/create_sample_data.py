from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth import get_user_model
from devices.models import Device, DeviceData, Shift
from datetime import datetime, time, timedelta
import random

User = get_user_model()

class Command(BaseCommand):
    help = 'Creates sample data for testing shift reports'

    def handle(self, *args, **options):
        self.stdout.write('Creating sample data...')

        # Create a test user if it doesn't exist
        user, created = User.objects.get_or_create(
            username='testuser',
            defaults={
                'email': 'test@example.com',
                'first_name': 'Test',
                'last_name': 'User'
            }
        )
        if created:
            user.set_password('testpass123')
            user.save()
            self.stdout.write(f'Created test user: {user.username}')

        # Create sample shifts if they don't exist
        shifts_data = [
            ('Morning Shift', time(6, 0), time(14, 0)),
            ('Evening Shift', time(14, 0), time(22, 0)),
            ('Night Shift', time(22, 0), time(6, 0)),
        ]

        for name, start_time, end_time in shifts_data:
            shift, created = Shift.objects.get_or_create(
                name=name,
                defaults={
                    'start_time': start_time,
                    'end_time': end_time,
                    'is_active': True
                }
            )
            if created:
                self.stdout.write(f'Created shift: {name}')

        # Create a sample device if it doesn't exist
        device, created = Device.objects.get_or_create(
            device_owner=user,
            device_address='192.168.1.100',
            defaults={
                'device_type': 'meter',
                'located_at': 'Factory Floor A',
                'address_type': 'ip',
                'is_active': True
            }
        )
        if created:
            self.stdout.write(f'Created device: {device}')

        # Generate sample device data for the past 3 days
        end_time = timezone.now()
        start_time = end_time - timedelta(days=3)

        # Remove existing sample data for this device to avoid duplicates
        DeviceData.objects.filter(device=device, timestamp__gte=start_time).delete()

        current_time = start_time
        current_kwh = 1000.0  # Starting kWh value

        sample_data = []
        while current_time <= end_time:
            # Simulate varying power factor, voltage, current
            power_factor = round(random.uniform(0.75, 0.95), 3)
            voltage = round(random.uniform(220, 240), 1)
            current = round(random.uniform(10, 50), 1)

            # Increment kWh slowly over time
            current_kwh += random.uniform(0.1, 0.5)
            kwah = current_kwh * 1.1  # Roughly 10% more for kVAh

            sample_data.append(DeviceData(
                device=device,
                timestamp=current_time,
                value={
                    'voltage': voltage,
                    'current': current,
                    'power_factor': power_factor,
                    'kwh': round(current_kwh, 1),
                    'kwah': round(kwah, 1)
                }
            ))

            # Add data every 5 minutes
            current_time += timedelta(minutes=5)

        # Bulk create the data
        DeviceData.objects.bulk_create(sample_data, batch_size=1000)

        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully created {len(sample_data)} sample data points for the past 3 days'
            )
        )

        self.stdout.write(
            self.style.SUCCESS(
                'Sample data creation complete! You can now generate shift reports.'
            )
        )

        self.stdout.write(
            'To generate shift reports, use the "Generate Reports" button in the web interface '
            'or run: python manage.py shell -c "from devices.views import generate_shift_reports_for_date; '
            'from datetime import date, timedelta; '
            'yesterday = date.today() - timedelta(days=1); '
            'print(f\'Generated {generate_shift_reports_for_date(yesterday)} reports for {yesterday}\')"'
        )