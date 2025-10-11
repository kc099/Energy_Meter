from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.utils import timezone
from django.conf import settings
from django.core.validators import RegexValidator

#the UserManager class for to define how the user is created and saved in the database

class UserManager(BaseUserManager):
    """Custom manager for User model where email is the unique identifier
    for authentication instead of usernames.
    """

#used for creating user
    def create_user(self, email, username, first_name='', last_name='', password=None, **extra_fields):
        if not email:
            raise ValueError('User must have an email address')

        if not username:
            raise ValueError('User must have a username')

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            first_name=first_name,
            last_name=last_name,
            **extra_fields,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
#used for creating superuser
    def create_superuser(self, email, username, first_name='', last_name='', password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, username, first_name, last_name, password, **extra_fields)

#this class defines the custom user model like scehema of the user table in the database
class User(AbstractBaseUser, PermissionsMixin):
    """Custom User model that uses email as the USERNAME_FIELD.

    Fields:
    - email (unique, used for login)
    - username (unique, public handle)
    - first_name, last_name
    - is_active, is_staff
    - date_joined
    """

    email = models.EmailField(max_length=255, unique=True)
    username = models.CharField(max_length=150, unique=True)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$',  message="Phone number must be entered in the format: '+999999999'. Up to 10 digits allowed.")
    phone_number = models.CharField(validators=[phone_regex], max_length=17, blank=True) # Validators should be a list

    # Email fields for reporting
    shift_manager_email = models.EmailField(max_length=255, blank=True, help_text="Email to receive shift reports")
    daily_manager_email = models.EmailField(max_length=255, blank=True, help_text="Email to receive daily reports")

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

#this functions are used to return string representation and full name and short name of the user and why we need them is to display the user in the admin panel
    def __str__(self):
        return f"{self.email} ({self.username})"

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    def get_short_name(self):
        return self.first_name or self.username

    def has_perm(self, perm, obj=None):
        return self.is_staff


class PasswordResetOTP(models.Model):
    """Stores time-bound OTP codes for resetting a user's password."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="password_reset_otps",
    )
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        status = "used" if self.used_at else "active"
        return f"OTP for {self.user.email} ({status})"

    def is_expired(self):
        return timezone.now() >= self.expires_at

    def mark_used(self):
        if not self.used_at:
            self.used_at = timezone.now()
            self.save(update_fields=["used_at"])


class ReportRecipient(models.Model):
    """Configures who receives automated reports for a given user."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="report_recipients",
    )
    email = models.EmailField()
    send_daily_reports = models.BooleanField(default=False)
    send_shift_reports = models.BooleanField(default=False)
    shifts = models.ManyToManyField(
        'devices.Shift',
        blank=True,
        related_name='report_recipients',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    last_failure_at = models.DateTimeField(null=True, blank=True)
    last_failure_message = models.TextField(blank=True)

    class Meta:
        unique_together = ('user', 'email')
        ordering = ['email']

    def __str__(self):
        return f"{self.email} ({self.user.email})"

    def requires_shift_selection(self) -> bool:
        return self.send_shift_reports and not self.shifts.exists()

    def last_status(self):
        if self.last_success_at:
            return 'success', self.last_success_at
        if self.last_failure_at:
            return 'failure', self.last_failure_at
        return 'pending', None
