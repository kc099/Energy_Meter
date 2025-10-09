from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import Device, DeviceProvisioningToken


class DeviceProvisioningTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            email='owner@example.com',
            username='owner',
            password='pass1234',
        )
        self._original_lifetime = DeviceProvisioningToken.DEFAULT_LIFETIME

    def tearDown(self):
        DeviceProvisioningToken.DEFAULT_LIFETIME = self._original_lifetime

    def _create_pending_device(self, address='192.168.0.10'):
        return Device.objects.create(
            device_type='meter',
            device_owner=self.user,
            located_at='Test Bench',
            device_address=address,
            address_type='ip',
            provisioning_state=Device.ProvisioningState.PENDING,
            is_active=False,
        )

    def test_purge_expired_pending_removes_device_without_active_token(self):
        DeviceProvisioningToken.DEFAULT_LIFETIME = timedelta(minutes=10)
        device = self._create_pending_device()
        DeviceProvisioningToken.objects.create(
            device=device,
            token_hash=DeviceProvisioningToken._hash('expired'),
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        stale_created_at = timezone.now() - DeviceProvisioningToken.DEFAULT_LIFETIME - timedelta(minutes=1)
        Device.objects.filter(pk=device.pk).update(created_at=stale_created_at)

        removed = Device.purge_expired_pending(owner=self.user)

        self.assertEqual(removed, 1)
        self.assertFalse(Device.objects.filter(pk=device.pk).exists())

    def test_purge_keeps_pending_device_with_active_token(self):
        DeviceProvisioningToken.DEFAULT_LIFETIME = timedelta(minutes=10)
        device = self._create_pending_device()
        DeviceProvisioningToken.issue(
            device,
            created_by=self.user,
            lifetime=timedelta(minutes=5),
        )

        removed = Device.purge_expired_pending(owner=self.user)

        self.assertEqual(removed, 0)
        self.assertTrue(Device.objects.filter(pk=device.pk).exists())

    def test_add_device_blocks_duplicate_when_pending_active(self):
        device = self._create_pending_device(address='192.168.0.25')
        DeviceProvisioningToken.issue(device, created_by=self.user)

        self.client.force_login(self.user)
        response = self.client.post(
            reverse('devices:add_device'),
            data={
                'device_type': 'meter',
                'located_at': 'Test Bench',
                'address_type': 'ip',
                'device_address': '192.168.0.25',
            },
        )

        form = response.context['form']
        self.assertEqual(response.status_code, 200)
        self.assertIn('device_address', form.errors)
        self.assertIn('already pending verification', form.errors['device_address'][0])
