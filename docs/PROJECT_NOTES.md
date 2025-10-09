# Project Notes – Recent Enhancements

_Last updated: 2025-10-09_

## Authentication Improvements
- Replaced email-link password reset with a 6-digit OTP workflow managed by `PasswordResetOTP` (see `accounts/models.py`, migration `0003`), backed by new request/verification views and templates (`accounts/views.py`, `templates/accounts/forgotPassword.html`, `templates/accounts/verifyResetOTP.html`).
- Added email templates for the OTP notifications (`templates/accounts/emails/password_reset_otp_email.*`).
- Introduced a change-password page using `PasswordChangeForm`, linked from the navigation menu (`accounts/views.py`, `templates/accounts/changePassword.html`, `templates/base.html`).

## Report Email Recipients
- Created `ReportRecipient` model/migration so each user can manage multiple report destinations with per-recipient preferences (`accounts/models.py`, migration `0004`).
- Added `ReportRecipientForm` and corresponding list/edit/delete views (`accounts/forms.py`, `accounts/views.py`) plus Bootstrap-styled templates (`templates/accounts/reportRecipients_list.html`, `_form.html`, `_confirm_delete.html`).
- Updated shift/daily report tasks to consume the new table, deduplicate addresses, and fall back to the legacy single-email fields (`devices/tasks.py`).

## Provisioning & Device Security
- Provisioning tokens now default to “no expiry”; entering minutes sets an optional timeout. This includes nullable `expires_at` fields, API/view changes, and template updates (`devices/models.py`, `device_gateway/models.py`, migrations `devices/0015`, `device_gateway/0004`, `api/views.py`, `device_gateway/views.py`, `devices/views.py`).
- Provisioning UIs show “No expiry” when appropriate and explain the new behaviour (`templates/devices/device_provision.html`, `templates/device_gateway/token_management.html`).
- Documentation refreshed to match the new defaults and password-protected revocation (`docs/PROVISIONING.md`, `docs/DEVICE_GATEWAY.md`).
- Revoking a device credential now requires the user’s password (updates at `devices/views.py`, `templates/devices/device_provision.html`).

## Infrastructure / Stability
- Celery fallback now exposes `.delay()`/`.apply_async()` even without Celery installed, preventing AttributeErrors during manual/device-driven polling (`devices/tasks.py`).
- Device provisioning tests reset the configurable lifetime to keep purge logic stable (`devices/tests.py`).

## Follow-Up Checklist
1. Export required env vars (e.g., `DJANGO_SECRET_KEY`) and run `python manage.py migrate` to apply new migrations.
2. Configure the email backend, then test the OTP password reset and change-password flows end-to-end.
3. Add report recipients via the new UI and verify daily/shift emails reach the correct inboxes.
4. Issue provisioning tokens with and without lifetimes; confirm the UI shows “No expiry” and history entries reflect the change.
5. Test credential revocation—it should prompt for the account password before clearing the device secret.

These notes capture everything changed so far and can be expanded as the project evolves.
