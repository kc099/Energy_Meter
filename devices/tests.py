from datetime import timedelta
import re

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import Device, DeviceProvisioningToken, DeviceTokenAccessOTP


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


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    DEFAULT_FROM_EMAIL='no-reply@example.com',
)
class DeviceTokenOTPTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            email='owner@example.com',
            username='owner',
            password='pass1234',
        )
        self.user.shift_manager_email = 'reports@example.com'
        self.user.save(update_fields=['shift_manager_email'])
        self.device = Device.objects.create(
            device_type='meter',
            device_owner=self.user,
            located_at='Test Bench',
            device_address='10.0.0.5',
            address_type='ip',
            provisioning_state=Device.ProvisioningState.ACTIVE,
            is_active=True,
        )
        self.current_token = self.device.issue_api_secret()
        mail.outbox.clear()

    def _request_otp(self):
        self.client.force_login(self.user)
        url = reverse('devices:device_token_request_otp', args=[self.device.id])
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn('otp_id', payload)
        self.assertIn('expires_at', payload)
        self.assertTrue(mail.outbox)
        body = mail.outbox[-1].body
        self.assertEqual(mail.outbox[-1].to, ['reports@example.com'])
        match = re.search(r'\b\d{6}\b', body)
        self.assertIsNotNone(match, body)
        return payload['otp_id'], match.group(0)

    def test_reveal_token_with_valid_otp(self):
        otp_id, otp_code = self._request_otp()
        reveal_url = reverse('devices:device_token_detail', args=[self.device.id])
        response = self.client.post(reveal_url, {'otp_id': otp_id, 'otp': otp_code})

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['token'], self.current_token)

        otp_entry = DeviceTokenAccessOTP.objects.get(id=otp_id)
        self.assertIsNotNone(otp_entry.verified_at)

    def test_reveal_token_with_wrong_otp_increments_attempts(self):
        otp_id, otp_code = self._request_otp()
        wrong_code = '000000'
        if wrong_code == otp_code:
            wrong_code = '111111'

        reveal_url = reverse('devices:device_token_detail', args=[self.device.id])
        response = self.client.post(reveal_url, {'otp_id': otp_id, 'otp': wrong_code})

        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertIn('error', data)

        otp_entry = DeviceTokenAccessOTP.objects.get(id=otp_id)
        self.assertEqual(otp_entry.attempt_count, 1)
        self.assertIsNone(otp_entry.verified_at)
