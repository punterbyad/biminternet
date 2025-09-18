from django import forms
from .models import Router, Transaction, VoucherUser, Withdraw, TransactionStatus

class RouterForm(forms.ModelForm):
    class Meta:
        model = Router
        # Don't expose balance on create/update form; it has a default and is managed server-side
        fields = ['name', 'location', 'type', 'ip_address', 'router_user', 'router_password']

class TransactionForm(forms.ModelForm):
    class Meta:
        model = Transaction
        fields = ['type', 'amount', 'reason', 'status', 'router']

class VoucherUserForm(forms.ModelForm):
    class Meta:
        model = VoucherUser
        fields = ['router', 'username']

class WithdrawForm(forms.ModelForm):
    class Meta:
        model = Withdraw
        fields = ['type', 'amount', 'status', 'user']

class TransactionStatusForm(forms.ModelForm):
    class Meta:
        model = TransactionStatus
        fields = ['reference', 'router', 'hotspot_name', 'profile', 'email', 'phone', 'status', 'payment_amount', 'currency', 'net_amount', 'payment_type', 'product', 'platform', 'status_history', 'created_from_ip', 'payment_method']
