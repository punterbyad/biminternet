from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages

def require_totp_setup(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        user = request.user
        # Must be authenticated AND must have completed TOTP enrollment
        if not user.is_authenticated:
            return redirect('accounts:login')
        if not getattr(user, 'totp_confirmed', False) or not getattr(user, 'totp_secret', ''):
            messages.warning(request, 'Please finish setting up your Authenticator app to continue.')
            return redirect('accounts:profile_wizard', step='1')
        return view_func(request, *args, **kwargs)
    return _wrapped
