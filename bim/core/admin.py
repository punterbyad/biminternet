from django.contrib import admin
from .models import Router, Transaction, VoucherUser, Withdraw, TransactionStatus

@admin.register(Router)
class RouterAdmin(admin.ModelAdmin):
    list_display = ('name', 'location', 'type', 'ip_address', 'balance', 'user')
    search_fields = ('name', 'location', 'ip_address')

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('type', 'amount', 'status', 'router', 'created_at')
    list_filter = ('type', 'status')
    search_fields = ('reason',)

@admin.register(VoucherUser)
class VoucherUserAdmin(admin.ModelAdmin):
    list_display = ('router', 'username')
    search_fields = ('username',)

@admin.register(Withdraw)
class WithdrawAdmin(admin.ModelAdmin):
    list_display = ('type', 'amount', 'status', 'user', 'created_at')
    list_filter = ('type', 'status')
    search_fields = ('user__email',)

@admin.register(TransactionStatus)
class TransactionStatusAdmin(admin.ModelAdmin):
    list_display = ('reference', 'router', 'status', 'payment_amount', 'currency', 'created_from_ip')
    list_filter = ('status', 'currency', 'payment_type')
    search_fields = ('reference', 'email', 'phone')
