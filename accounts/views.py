from datetime import timedelta
import secrets

from django.conf import settings
from django.contrib import messages, auth
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.core.mail import send_mail
from django.db import IntegrityError
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.utils import timezone

from devices.models import Device, DeviceShare

from .models import PasswordResetOTP, ReportRecipient, User
from .forms import ReportRecipientForm, UserForm



#function or view or api to register the user
# Create your views here.
# API : /register and it is a post request


def RegisterView(request):
    if request.user.is_authenticated:
        messages.warning(request, 'You are already logged in!')
        return redirect('dashboard')
    elif request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            
            # Create the user using create_user method
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = User.objects.create_user(first_name=first_name, last_name=last_name, username=username, email=email, password=password)
            user.save()

            messages.success(request, 'Your account has been registered successfully!')
            return redirect('login')
        else:
            print(form.errors)
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserForm()
    
    context = {
        'form': form,
    }
    return render(request, 'accounts/register.html', context)




def LoginView(request):
    if request.user.is_authenticated:
        messages.warning(request, 'you are already logged in!')
        return redirect('dashboard')
    
    elif request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)
        if user is not None:
            auth.login(request, user)
            messages.success(request, 'you are now logged in!')
            return redirect('dashboard')
        else:
            messages.error(request, 'invalid login credentials')
            return redirect('login')
    return render(request, 'accounts/login.html')

def logoutView(request):
    if request.user.is_authenticated:
        auth.logout(request)
        messages.success(request, 'you are logged out!')
        return redirect('login')


@login_required(login_url='login')
def DashboardView(request):
    devices_qs = (
        Device.objects.filter(
            Q(device_owner=request.user) | Q(shared_with=request.user)
        )
        .select_related('device_owner')
        .prefetch_related('device_shares__user')
        .order_by('-created_at')
        .distinct()
    )

    devices = list(devices_qs)
    owned_device_ids = {device.id for device in devices if device.device_owner_id == request.user.id}
    config_access_ids = set(owned_device_ids)

    for device in devices:
        if device.device_owner_id == request.user.id:
            role = DeviceShare.AccessLevel.MANAGER
        else:
            share = next(
                (share for share in device.device_shares.all() if share.user_id == request.user.id),
                None,
            )
            role = share.role if share else None
        device.access_role = role
        if role:
            try:
                device.access_role_label = DeviceShare.AccessLevel(role).label
            except ValueError:
                device.access_role_label = ''
        else:
            device.access_role_label = ''

        if role in (
            DeviceShare.AccessLevel.INSPECTOR,
            DeviceShare.AccessLevel.MANAGER,
        ):
            config_access_ids.add(device.id)

    total_devices = len(devices)
    active_devices = sum(1 for device in devices if device.is_active)
    inactive_devices = total_devices - active_devices

    return render(
        request,
        'accounts/myaccount.html',
        {
            'devices': devices,
            'device_totals': {
                'total': total_devices,
                'active': active_devices,
                'inactive': inactive_devices,
            },
            'owned_device_ids': list(owned_device_ids),
            'config_access_ids': list(config_access_ids),
        },
    )

def _generate_otp(length: int = 6) -> str:
    return ''.join(str(secrets.randbelow(10)) for _ in range(length))


def _send_password_reset_otp(user: User, code: str) -> None:
    context = {"user": user, "code": code}
    subject = "Edgesync password reset code"
    plain_body = render_to_string(
        "accounts/emails/password_reset_otp_email.txt",
        context,
    )
    html_body = render_to_string(
        "accounts/emails/password_reset_otp_email.html",
        context,
    )
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None)
    send_mail(
        subject,
        plain_body,
        from_email,
        [user.email],
        html_message=html_body,
    )


def _add_form_control_classes(form):
    for field in form.fields.values():
        existing = field.widget.attrs.get('class', '')
        pieces = {cls for cls in existing.split() if cls}
        pieces.add('form-control')
        field.widget.attrs['class'] = ' '.join(sorted(pieces))


def ForgotPasswordView(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        if not email:
            messages.error(request, 'Please enter the email associated with your account.')
            return redirect('forgot_password')

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            messages.error(request, 'Account does not exist for the provided email.')
            return redirect('forgot_password')

        code = _generate_otp()
        expires_at = timezone.now() + timedelta(minutes=10)
        PasswordResetOTP.objects.filter(
            user=user,
            used_at__isnull=True,
        ).update(used_at=timezone.now())
        otp = PasswordResetOTP.objects.create(
            user=user,
            code=code,
            expires_at=expires_at,
        )

        try:
            _send_password_reset_otp(user, code)
        except Exception:
            otp.delete()
            messages.error(request, 'We could not send the OTP email. Please try again later.')
            return redirect('forgot_password')

        request.session['password_reset_email'] = user.email
        messages.success(
            request,
            'We sent a one-time passcode to your email. Enter it below to reset your password.',
        )
        return redirect('verify_reset_otp')

    prefilled_email = request.session.get('password_reset_email', '')
    return render(
        request,
        'accounts/forgotPassword.html',
        {'prefilled_email': prefilled_email},
    )


def VerifyResetOTPView(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        otp_code = request.POST.get('otp', '').strip()
        new_password1 = request.POST.get('new_password1', '')
        new_password2 = request.POST.get('new_password2', '')

        if email:
            request.session['password_reset_email'] = email

        if not all([email, otp_code, new_password1, new_password2]):
            messages.error(request, 'All fields are required to reset your password.')
            return redirect('verify_reset_otp')

        if new_password1 != new_password2:
            messages.error(request, 'New passwords do not match.')
            return redirect('verify_reset_otp')

        if not otp_code.isdigit() or len(otp_code) != 6:
            messages.error(request, 'The passcode must be a 6-digit number.')
            return redirect('verify_reset_otp')

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            messages.error(request, 'No account found for the provided email.')
            return redirect('verify_reset_otp')

        otp = (
            PasswordResetOTP.objects.filter(
                user=user,
                code=otp_code,
                used_at__isnull=True,
            )
            .order_by('-created_at')
            .first()
        )

        if not otp:
            messages.error(request, 'Invalid passcode. Please check the code and try again.')
            return redirect('verify_reset_otp')

        if otp.is_expired():
            otp.mark_used()
            messages.error(request, 'That passcode has expired. Please request a new one.')
            return redirect('forgot_password')

        user.set_password(new_password1)
        user.save()

        otp.mark_used()
        PasswordResetOTP.objects.filter(
            user=user,
            used_at__isnull=True,
        ).exclude(pk=otp.pk).update(used_at=timezone.now())

        request.session.pop('password_reset_email', None)
        messages.success(request, 'Your password has been reset. You can sign in now.')
        return redirect('login')

    prefilled_email = request.session.get('password_reset_email', '')
    return render(
        request,
        'accounts/verifyResetOTP.html',
        {'prefilled_email': prefilled_email},
    )


@login_required(login_url='login')
def ChangePasswordView(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password has been updated.')
            return redirect('change_password')
    else:
        form = PasswordChangeForm(request.user)

    _add_form_control_classes(form)
    return render(request, 'accounts/changePassword.html', {'form': form})


@login_required(login_url='login')
def ReportRecipientListView(request):
    recipients = (
        request.user.report_recipients.all()
        .prefetch_related('shifts')
        .order_by('email')
    )

    if request.method == 'POST':
        form = ReportRecipientForm(data=request.POST, user=request.user)
        if form.is_valid():
            try:
                form.save()
            except IntegrityError:
                form.add_error('email', 'You already have a recipient with this email address.')
            else:
                messages.success(request, 'Recipient added successfully.')
                return redirect('report_recipients')
    else:
        form = ReportRecipientForm(user=request.user)

    return render(
        request,
        'accounts/reportRecipients_list.html',
        {
            'form': form,
            'recipients': recipients,
        },
    )


@login_required(login_url='login')
def ReportRecipientUpdateView(request, pk):
    recipient = get_object_or_404(ReportRecipient, pk=pk, user=request.user)

    if request.method == 'POST':
        form = ReportRecipientForm(
            data=request.POST,
            instance=recipient,
            user=request.user,
        )
        if form.is_valid():
            try:
                form.save()
            except IntegrityError:
                form.add_error('email', 'You already have a recipient with this email address.')
            else:
                messages.success(request, 'Recipient updated successfully.')
                return redirect('report_recipients')
    else:
        form = ReportRecipientForm(instance=recipient, user=request.user)

    return render(
        request,
        'accounts/reportRecipient_form.html',
        {
            'form': form,
            'recipient': recipient,
        },
    )


@login_required(login_url='login')
def ReportRecipientDeleteView(request, pk):
    recipient = get_object_or_404(ReportRecipient, pk=pk, user=request.user)

    if request.method == 'POST':
        recipient.delete()
        messages.success(request, 'Recipient removed successfully.')
        return redirect('report_recipients')

    return render(
        request,
        'accounts/reportRecipient_confirm_delete.html',
        {'recipient': recipient},
    )
