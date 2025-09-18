from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, KYC
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    model = User
    list_display = ('phone_number','email','first_name','last_name','totp_confirmed','is_staff')
    ordering = ('phone_number',)
    fieldsets = (
        (None, {'fields': ('phone_number','password')}),
        ('Personal', {'fields': ('first_name','last_name','email','company','city')}),
        ('Permissions', {'fields': ('is_active','is_staff','is_superuser','groups','user_permissions')}),
        ('Status', {'fields': ('kyc_status','totp_confirmed')}),
    )
    add_fieldsets = ((None, {'classes': ('wide',), 'fields': ('phone_number','email','password1','password2')}),)
  
@admin.register(KYC)
class KYCAdmin(admin.ModelAdmin):
    list_display = ('user', 'provider', 'status', 'updated_at')
    readonly_fields = ('raw_response',)

