from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model

User = get_user_model()


class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('phone_number', 'email', 'first_name', 'last_name', 'password1', 'password2')


class InvitationAcceptForm(forms.Form):
    email = forms.EmailField()
    password1 = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get('password1') != cleaned_data.get('password2'):
            self.add_error('password2', 'Passwords do not match.')
        return cleaned_data


class InviteForm(forms.Form):
    invitation_email = forms.EmailField(label="Invitee email")
    role = forms.ChoiceField(choices=[('finance', 'Finance'), ('auditor', 'Auditor')], initial='finance')

    def clean_invitation_email(self):
        email = self.cleaned_data['invitation_email']
        return email.lower().strip()


class SignUpForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('phone_number', 'email', 'first_name', 'last_name')  # removed company + city

    def save(self, commit=True):
        u = super().save(commit=False)
        u.totp_confirmed = False
        if commit:
            u.save()
        return u


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'company', 'city', 'email')


class LoginForm(forms.Form):
    phone_number = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "phoneInput",
                "placeholder": "e.g. 772404040",
                "inputmode": "tel",
            }
        )
    )

    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control pass-input",  # 'pass-input' used by the eye-toggle JS
                "placeholder": "••••••••",
                "autocomplete": "current-password",
            }
        )
    )
    
class TOTPForm(forms.Form):
    code = forms.CharField(
        max_length=10,
        widget=forms.TextInput(attrs={"class": "form-control"})
    )
 
class LostPhoneLoginForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            "class": "form-control",
            "placeholder": "Enter your email",
            "id": "lostphone-email",
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            "class": "form-control",
            "placeholder": "Enter your password",
            "id": "lostphone-password",   # 👈 important
        })
    )

class OTPVerifyForm(forms.Form):
    otp = forms.CharField(
        max_length=8,
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "Enter OTP"
        })
    )
