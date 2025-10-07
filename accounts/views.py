from django.shortcuts import render
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.db.models import Q

from devices.models import Device, DeviceShare

from .models import User
from .forms import UserForm



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

def ForgotPasswordView(request):
    if request.method == 'POST':
        email = request.POST['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email__exact=email)
            mail_subject = 'Reset your password'
            email_template = 'accounts/emails/reset_password_email.html'
            send_verification_email(request, user, mail_subject, email_template)
            messages.success(request, 'Password reset email has been sent to your email address.')
            return redirect('login')
        else:
            messages.error(request, 'Account does not exist!')
            return redirect('forgot_password')
    return render(request, 'accounts/forgotPassword.html')

def ResetpasswordView_validate(request, uidb64, token):
    return render(request, 'accounts/resetPassword.html')

def ResetPasswordView(request):
    return render(request, 'accounts/resetPassword.html')
