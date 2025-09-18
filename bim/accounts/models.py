from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from phonenumber_field.modelfields import PhoneNumberField
import uuid

class UserManager(BaseUserManager):
    def create_user(self, phone_number, email, password=None, **extra):
        if not phone_number: raise ValueError('phone_number required')
        if not email: raise ValueError('email required')
        user = self.model(phone_number=phone_number, email=email, **extra)
        user.set_password(password); user.save(using=self._db); return user
    def create_superuser(self, phone_number, email, password=None, **extra):
        extra.setdefault('is_staff', True); extra.setdefault('is_superuser', True)
        return self.create_user(phone_number, email, password, **extra)

class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class UserTypes(models.TextChoices):
        USER = 'user', 'User'
        MANAGER = 'manager', 'Manager'
        ADMIN = 'admin', 'Admin'

    phone_number = PhoneNumberField(unique=True)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    company = models.CharField(max_length=200, blank=True)
    city = models.CharField(max_length=100, blank=True)
    user_type = models.CharField(max_length=16, choices=UserTypes.choices, default=UserTypes.USER)
    # role is per-account, see AccountMembership below

    # Invitations sent by this user
    # invitations_sent = related_name in AccountMembership

    # Security / auth
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=128, blank=True, null=True)
    totp_confirmed = models.BooleanField(default=False)

    # Other
    sms_enabled = models.BooleanField(default=False)
    kyc_status = models.CharField(max_length=12, default='none')
    date_joined = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)
    # Accounts this user is a member of
    # AccountMembership has two foreign keys to User (user, invited_by). Specify
    # through_fields to disambiguate which fields map the relation.
    accounts = models.ManyToManyField('Account', through='AccountMembership', through_fields=('user', 'account'), related_name='users')

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['email']

    objects = UserManager()

    def __str__(self):
        return str(self.phone_number)


# Account model for resource ownership and sharing
class Account(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    owner = models.ForeignKey(User, related_name='owned_accounts', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

# Membership and role per account
class AccountMembership(models.Model):
    ROLE_CHOICES = [
        ('owner', 'Owner'),
        ('finance', 'Finance'),
        ('auditor', 'Auditor'),
    ]
    # user may be null for pending invitations (email-only invites)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    invited_by = models.ForeignKey(User, related_name='invitations_sent', on_delete=models.SET_NULL, null=True, blank=True)
    invitation_email = models.EmailField(blank=True, null=True)
    accepted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

class KYC(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    """
    Stores the latest KYC status per user.
    Always overwritten with the newest result.
    """
    PROVIDERS = [
        ('sumsub', 'Sumsub'),
        ('veriff', 'Veriff'),
    ]

    STATUS_CHOICES = [
        ("init", "Init"),
        ("pending", "Pending"),
        ("queued", "Queued"),
        ("onHold", "On Hold"),
        ("prechecked", "Prechecked"),
        ("completed", "Completed"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="kyc"
    )
    provider = models.CharField(max_length=32, choices=PROVIDERS)
    external_id = models.CharField(max_length=200, blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    raw_response = models.JSONField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"KYC for {self.user} via {self.provider} - {self.status}"

class KYCResult(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    """
    Stores raw webhook events from Sumsub (or other providers later).
    Multiple per user = full audit log.
    """
    PROVIDERS = [
        ('sumsub', 'Sumsub'),
        ('veriff', 'Veriff'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="kyc_results")
    provider = models.CharField(max_length=32, choices=PROVIDERS, default="sumsub")
    applicant_id = models.CharField(max_length=255, blank=True, null=True)
    inspection_id = models.CharField(max_length=255, blank=True, null=True)
    correlation_id = models.CharField(max_length=255, blank=True, null=True)
    level_name = models.CharField(max_length=255, blank=True, null=True)
    event_type = models.CharField(max_length=255)  # e.g. applicantCreated, applicantReviewed
    review_status = models.CharField(max_length=100, blank=True, null=True)  # queued, completed, etc.
    review_answer = models.CharField(max_length=100, blank=True, null=True)  # green, red, etc.
    raw_payload = models.JSONField()  # store full webhook JSON
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"[{self.provider}] {self.user} - {self.event_type} - {self.review_status}"
