from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
User = get_user_model()
class EmailOrPhoneBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None: return None
        try:
            u = User.objects.filter(phone_number__exact=username).first()
            if u and u.check_password(password): return u
        except: pass
        try:
            u = User.objects.filter(email__iexact=username).first()
            if u and u.check_password(password): return u
        except: pass
        return None
