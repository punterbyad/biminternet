# =========================
# Imports
# =========================
from django.shortcuts import render, redirect, get_object_or_404
from django.views import View
from django.core.cache import cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_backends, get_user_model
from django.contrib.auth.views import LoginView
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.utils.dateparse import parse_datetime
from django.utils import timezone
from django.db.models import Sum
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from requests.exceptions import HTTPError
from django.db import transaction
import pyotp, qrcode, io, base64, os, json, random, logging, time
from uuid import uuid4
# App imports
from .forms import (
    CustomUserCreationForm, InvitationAcceptForm, SignUpForm, ProfileForm, LoginForm, TOTPForm, LostPhoneLoginForm, OTPVerifyForm
)
from .models import User, Account, AccountMembership, KYC, KYCResult
from core.models import VoucherUser, Transaction, Router
from .utils import make_otp, store_otp, verify_otp, increment_throttle, allowed_to_send, seconds_until_available, fetch_killbill_context
from .kyc_providers import sumsub_generate_sdk_token
from .decorators import require_totp_setup
from .egosms import EgoSMSService

User = get_user_model()
logger = logging.getLogger(__name__)


# Helper: embed a small logo (favicon) into the center of a QR PIL image.
# This is optional and fails open if Pillow or staticfiles finders aren't available.
def embed_logo_in_qr(pil_img, logo_rel_path=None):
    try:
        # Local imports so missing optional deps don't break module import
        from PIL import Image
        from django.contrib.staticfiles import finders
    except Exception:
        return pil_img

    logo_rel_path = logo_rel_path or getattr(settings, 'TOTP_QR_LOGO', 'img/favicon.ico')
    logo_path = None
    try:
        logo_path = finders.find(logo_rel_path)
    except Exception:
        logo_path = None

    if not logo_path:
        return pil_img

    try:
        logo = Image.open(logo_path).convert("RGBA")
        pil_img = pil_img.convert("RGBA")
        img_w, img_h = pil_img.size

        # Logo scale (fraction of QR size)
        factor = float(getattr(settings, 'TOTP_QR_LOGO_SCALE', 0.20))
        logo_size = max(16, int(min(img_w, img_h) * factor))

        # Best available resampling attribute for compatibility
        resample = getattr(Image, 'Resampling', Image).LANCZOS if hasattr(Image, 'Resampling') else Image.ANTIALIAS
        logo = logo.resize((logo_size, logo_size), resample)

        pos = ((img_w - logo_size) // 2, (img_h - logo_size) // 2)
        pil_img.paste(logo, pos, logo)
        return pil_img
    except Exception:
        # If anything goes wrong, return original QR to avoid breaking flow
        return pil_img

# =========================
# Registration & Invitation
# =========================

class CustomLoginView(LoginView):
    template_name = 'accounts/login.html'

@login_required
def accept_invitation(request, membership_id):
    membership = get_object_or_404(AccountMembership, id=membership_id, accepted=False)
    if request.method == 'POST':
        form = InvitationAcceptForm(request.POST)
        if form.is_valid():
            membership.accepted = True
            membership.save()
            messages.success(request, 'Invitation accepted.')
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': True, 'membership_id': str(membership.id)})
            return redirect('dashboard')
    else:
        form = InvitationAcceptForm(initial={'email': membership.invitation_email})
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({'membership': {'id': str(membership.id), 'invitation_email': membership.invitation_email, 'accepted': membership.accepted}})
    return render(request, 'accounts/accept_invitation.html', {'form': form, 'membership': membership})


@login_required
def invite_account_member(request, account_id):
    """Allow an account owner to invite another user to their account.

    Creates an AccountMembership with accepted=False and stores invitation_email.
    The owner can choose a role (finance/auditor)."""
    from .forms import InviteForm
    from .models import Account, AccountMembership

    account = get_object_or_404(Account, id=account_id)
    # Only owner may invite
    if account.owner_id != request.user.id:
        messages.error(request, 'Only the account owner may invite members.')
        return redirect('accounts:dashboard_home')

    if request.method == 'POST':
        form = InviteForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['invitation_email']
            role = form.cleaned_data['role']
            # Invitations should not set `user` to the inviter; leave `user` null so the
            # template shows the `invitation_email` (the invitee) instead of the sender.
            membership = AccountMembership.objects.create(
                user=None,
                account=account,
                role=role,
                invited_by=request.user,
                invitation_email=email,
                accepted=False,
            )

            # Send an email invitation with an accept link
            try:
                from django.template.loader import render_to_string
                from django.core.mail import EmailMultiAlternatives
                from django.urls import reverse

                accept_url = request.build_absolute_uri(reverse('accounts:accept_invitation', args=[membership.id]))
                ctx = {
                    'account': account,
                    'inviter_name': (getattr(request.user, 'get_full_name', None) and request.user.get_full_name()) or getattr(request.user, 'email', None) or getattr(request.user, 'username', str(request.user.pk)),
                    'accept_url': accept_url,
                    'site_name': getattr(settings, 'PROJECT_NAME', 'Our App')
                }
                subject = f"You've been invited to join {account.name}"
                text_body = render_to_string('emails/invite.txt', ctx)
                html_body = render_to_string('emails/invite.html', ctx)
                email_msg = EmailMultiAlternatives(subject=subject, body=text_body, from_email=settings.DEFAULT_FROM_EMAIL, to=[email])
                email_msg.attach_alternative(html_body, 'text/html')
                email_msg.send(fail_silently=False)
            except Exception:
                logger.exception('Failed to send invitation email to %s', email)

            messages.success(request, f'Invitation sent to {email}')
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': True, 'invitation_email': email})
            # Redirect back to the access management page for this account so the
            # success message is shown on the access list rather than the dashboard.
            return redirect('accounts:access_management', account_id=account.id)
    else:
        form = InviteForm()

    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({'form_fields': list(form.fields.keys()), 'account_id': str(account.id)})
    return render(request, 'accounts/invite_member.html', {'form': form, 'account': account})


@require_POST
def client_log(request):
    """Endpoint for client-side logging from the Access Management page.

    Accepts a JSON body or form-encoded POST and writes it to the server logger
    so you can inspect client-side results when DevTools aren't available.
    """
    try:
        payload = {}
        if request.content_type and 'application/json' in request.content_type:
            payload = json.loads(request.body.decode('utf-8') or '{}')
        else:
            payload = request.POST.dict()
    except Exception as e:
        payload = {'_parse_error': str(e)}

    # Attach some useful request context
    ctx = {
        'path': request.path,
        'method': request.method,
        'remote_addr': request.META.get('REMOTE_ADDR'),
        'payload': payload,
    }
    logger.info('CLIENT-LOG: %s', ctx)
    return JsonResponse({'ok': True})

# =========================
# Signup, Profile, TOTP
# =========================
class SignUpView(View):

    def get(self, request):
        form = SignUpForm()
        return render(request, "accounts/signup.html", {"form": form})

    @transaction.atomic
    def post(self, request):
        try:
            post_data = request.POST.copy()
            phone = post_data.get("phone_number", "")
            if phone and not phone.startswith("+"):
                cleaned_phone = phone.replace("+", "")
                if cleaned_phone.startswith("256") and len(cleaned_phone) == 12:
                    post_data["phone_number"] = "+" + cleaned_phone
                elif cleaned_phone.startswith("0") and len(cleaned_phone) == 10:
                    post_data["phone_number"] = "+256" + cleaned_phone[1:]
                else:
                    post_data["phone_number"] = "+" + cleaned_phone

            form = SignUpForm(post_data)

            if not form.is_valid():
                logger.warning("Signup form invalid: %s", form.errors)
                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({'success': False, 'errors': form.errors}, status=400)
                return render(request, "accounts/signup.html", {"form": form})

            full_phone = form.cleaned_data["phone_number"]
            otp_verified = request.session.get("otp_verified")
            otp_phone = request.session.get("otp_phone")
            session_phone_clean = str(otp_phone).replace('+', '') if otp_phone else ""
            form_phone_clean = str(full_phone).replace('+', '') if full_phone else ""

            if otp_verified is not True or session_phone_clean != form_phone_clean:
                logger.warning(
                    "OTP mismatch: verified=%s session_phone=%s form_phone=%s",
                    otp_verified, session_phone_clean, form_phone_clean
                )
                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({'success': False, 'otp_error': 'OTP verification failed.'}, status=400)
                return render(request, "accounts/signup.html", {
                    "form": form,
                    "otp_error": "OTP verification failed. Please complete OTP verification."
                })

            user = form.save(commit=False)
            user.totp_confirmed = False
            user.set_password(form.cleaned_data["password1"])
            user.save()

            login(request, user)
            for key in ["otp_code", "otp_phone", "otp_verified"]:
                request.session.pop(key, None)

            logger.info("User %s registered successfully", user.id)
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': True, 'redirect': '/accounts/profile_wizard/1'})
            return redirect("accounts:profile_wizard", step="1")

        except Exception as e:
            logger.exception("Registration failed: %s", e)
            transaction.set_rollback(True)
            messages.error(request, "Registration failed. Please try again in a few moments.")
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': False, 'error': 'Registration failed'}, status=500)
            return render(
                request,
                "accounts/signup.html",
                {"form": form if 'form' in locals() else SignUpForm()}
            )

          
@method_decorator(login_required, name='dispatch')
class ProfileEditView(View):
    def get(self, request):
        form = ProfileForm(instance=request.user); return render(request, 'accounts/profile_edit.html', {'form': form})
    def post(self, request):
        form = ProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile saved. Now set up your authenticator.')
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': True, 'redirect': '/accounts/totp_setup/'})
            return redirect('accounts:totp_setup')
        return render(request, 'accounts/profile_edit.html', {'form': form})

class TOTPSetupView(View):
    template_name = 'accounts/totp_setup.html'

    @method_decorator(login_required)
    def get(self, request):
        user = request.user

        # If already confirmed, just go to dashboard
        if user.totp_confirmed and user.totp_secret:
            messages.info(request, "You’ve already set up Authenticator.")
            return redirect('accounts:dashboard_home')

        # Generate a fresh secret if none in session
        secret = request.session.get('totp_setup_secret')
        if not secret:
            secret = pyotp.random_base32()
            request.session['totp_setup_secret'] = secret

        issuer = getattr(settings, 'PROJECT_NAME', os.getenv('PROJECT_NAME', 'BimInternet'))
        otpauth = pyotp.totp.TOTP(secret).provisioning_uri(
            name=str(user.phone_number),
            issuer_name=issuer
        )

        # Generate QR code and optionally embed logo
        img = qrcode.make(otpauth)
        try:
            img = embed_logo_in_qr(img)
        except Exception:
            pass
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        form = TOTPForm()
        ctx = {'qr_b64': qr_b64, 'secret': secret, 'form': form}
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'qr_b64': qr_b64, 'secret': secret})
        return render(request, self.template_name, ctx)

    @method_decorator(login_required)
    def post(self, request):
        form = TOTPForm(request.POST)
        secret = request.session.get('totp_setup_secret')

        if not secret:
            messages.error(request, 'No TOTP session found. Please restart setup.')
            return redirect('accounts:totp_setup')

        if form.is_valid():
            code = form.cleaned_data['code']
            totp = pyotp.TOTP(secret)

            if totp.verify(code):
                # Save to user
                user = request.user
                user.totp_secret = secret
                user.totp_confirmed = True
                user.save()

                # Cleanup session
                request.session['twofa_verified'] = True
                request.session.pop('totp_setup_secret', None)

                messages.success(request, 'Authenticator setup complete.')
                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({'success': True, 'redirect': '/dashboard/'})
                return redirect('accounts:dashboard_home')
            else:
                messages.error(request, 'Invalid code. Please try again.')

        # If invalid form or code, regenerate QR so the template still works
        issuer = getattr(settings, 'PROJECT_NAME', os.getenv('PROJECT_NAME', 'Smartwire'))
        otpauth = pyotp.totp.TOTP(secret).provisioning_uri(
            name=str(request.user.phone_number),
            issuer_name=issuer
        )
        img = qrcode.make(otpauth)
        try:
            img = embed_logo_in_qr(img)
        except Exception:
            pass
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        ctx = {'form': form, 'qr_b64': qr_b64, 'secret': secret}
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'success': False, 'error': 'Invalid code', 'qr_b64': qr_b64})
        return render(request, self.template_name, ctx)

class LoginView(View):
    def get(self, request):
        form = LoginForm()
        return render(request, 'accounts/login.html', {'form': form})

    def post(self, request):
        form = LoginForm(request.POST)
        if not form.is_valid():
            return render(request, 'accounts/login.html', {'form': form})

        phone = form.cleaned_data['phone_number']
        password = form.cleaned_data['password']
        
        user = authenticate(request, username=phone, password=password)
        if user:
            # Store the PK for the TOTP step (stringified to avoid session JSON issues for UUID PKs)
            request.session['pre_2fa_user_pk'] = str(user.pk)
            request.session['temp_password'] = password  # optional if you need re-authentication
            # No backend stored here; final login will use the first configured backend
            logger.info('Login succeeded for phone=%s user=%s totp_confirmed=%s', phone, getattr(user, 'pk', None), getattr(user, 'totp_confirmed', False))
            # Log session snapshot (keys only) so we can trace flow
            logger.debug('Session keys after initial authenticate: %s', list(request.session.keys()))
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': True, 'redirect': '/accounts/login/totp/'})
            return redirect('accounts:login_totp')
        else:
            messages.error(request, 'Invalid phone number or password.')
            logger.info('Login failed for phone=%s', phone)
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': False, 'error': 'Invalid phone or password'}, status=400)
            return render(request, 'accounts/login.html', {'form': form})

class LoginTOTPView(View):
    def get(self, request):
        form = OTPVerifyForm()
        return render(request, 'accounts/login_totp.html', {'form': form})

    def post(self, request):
        form = OTPVerifyForm(request.POST)
        if not form.is_valid():
            return render(request, 'accounts/login_totp.html', {'form': form})

        pk = request.session.get('pre_2fa_user_pk')
        logger.debug('pre_2fa_user_pk from session: %s', pk)
        logger.debug('Session keys at start of TOTP verify: %s', list(request.session.keys()))
        # Useful to see if a 'next' param is present (can cause redirect loops in some setups)
        try:
            next_param = request.GET.get('next') or request.POST.get('next')
        except Exception:
            next_param = None
        logger.debug('TOTP verify next param: %s; referer: %s', next_param, request.META.get('HTTP_REFERER'))
        if not pk:
            messages.error(request, 'Session expired. Please log in again.')
            return redirect('accounts:login')

        # Session stores stringified PK for UUID compatibility; convert if necessary
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            messages.error(request, 'User not found.')
            return redirect('accounts:login')

        otp_input = form.cleaned_data['otp']
        # Protect against missing or invalid TOTP secret on the user record
        secret = getattr(user, 'totp_secret', None)
        logger.debug('User %s totp_confirmed=%s totp_secret_present=%s', getattr(user,'pk',None), getattr(user,'totp_confirmed',False), bool(secret))
        if not secret:
            logger.warning("User %s attempted TOTP login but has no TOTP secret", getattr(user, 'pk', None))
            # Clear the pre-2fa session to avoid re-entering this flow repeatedly
            request.session.pop('pre_2fa_user_pk', None)
            request.session.pop('temp_password', None)
            messages.error(request, 'Two-factor authentication is not configured for this account. Please log in and set up an authenticator in your profile.')
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': False, 'error': 'two_factor_not_configured'}, status=400)
            # Render the login template directly (avoid redirect loops caused by `next=` query params)
            form = LoginForm()
            logger.debug('Rendering login form to user after missing TOTP secret; session cleared; session keys: %s', list(request.session.keys()))
            return render(request, 'accounts/login.html', {'form': form})

        try:
            totp = pyotp.TOTP(secret)
            verified = totp.verify(otp_input)
            logger.info('TOTP verify attempted for user %s: result=%s', getattr(user,'pk',None), bool(verified))
        except Exception as e:
            logger.exception('Error verifying TOTP for user %s: %s', getattr(user, 'pk', None), str(e))
            messages.error(request, 'Error verifying the one-time code. Please try again.')
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': False, 'error': 'verification_error'}, status=500)
            return render(request, 'accounts/login_totp.html', {'form': form})

        if verified:
            # Use the first configured authentication backend for final login
            backend = get_backends()[0]
            backend_str = f"{backend.__module__}.{backend.__class__.__name__}"

            # Finalize login and clear temporary pre-2fa session state
            login(request, user, backend=backend_str)
            # Configure per-session expiry: mobile/remembered clients keep a long-lived
            # session; web sessions should expire after an idle timeout.
            try:
                mobile_flag = request.POST.get('remember') == '1' or request.headers.get('X-Mobile-Client') == '1' or request.GET.get('mobile') == '1'
                if mobile_flag:
                    # mark session as mobile/remembered for later checks
                    request.session['mobile_client'] = True
                    request.session.set_expiry(getattr(settings, 'MOBILE_SESSION_TIMEOUT', 60 * 60 * 24 * 30))
                else:
                    # Idle expiry: set_expiry(seconds) plus SESSION_SAVE_EVERY_REQUEST=True
                    # ensures the expiry is refreshed on each request.
                    request.session.set_expiry(getattr(settings, 'WEB_SESSION_IDLE_TIMEOUT', 20 * 60))
            except Exception:
                # If session backend doesn't support expiry, ignore and continue
                logger.exception('Failed to set session expiry for user %s', getattr(user, 'pk', None))
            logger.debug('User %s logged in via TOTP; authenticated=%s', getattr(user, 'pk', None), getattr(request.user, 'is_authenticated', None))
            request.session.pop('pre_2fa_user_pk', None)
            request.session.pop('temp_password', None)
            request.session['twofa_verified'] = True

            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': True, 'redirect': '/dashboard/'})
            return redirect('accounts:dashboard_home')
        else:
            messages.error(request, 'Invalid OTP.')
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': False, 'error': 'Invalid OTP'}, status=400)
            return render(request, 'accounts/login_totp.html', {'form': form})

class LostPhoneStartView(View):
    def get(self, request):
        form = LostPhoneLoginForm(); return render(request, 'accounts/lost_phone_start.html', {'form': form})
    def post(self, request):
        form = LostPhoneLoginForm(request.POST)
        if not form.is_valid(): return render(request, 'accounts/lost_phone_start.html', {'form': form})
        email = form.cleaned_data['email']; pwd = form.cleaned_data['password']
        user = authenticate(request, username=email, password=pwd)
        if not user:
            messages.error(request, 'Invalid email/password')
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': False, 'error': 'Invalid email/password'}, status=400)
            return render(request, 'accounts/lost_phone_start.html', {'form': form})
        ident = f'email:{email}'
        if not allowed_to_send('email_otp', ident):
            secs = seconds_until_available('email_otp', ident)
            messages.error(request, f'Too many requests. Try again in {secs} seconds.'); return render(request, 'accounts/lost_phone_start.html', {'form': form, 'wait_seconds': secs})
        code = make_otp(); key = f'otp:email:{user.pk}'; store_otp(key, code, ttl=600)
        from django.core.mail import send_mail
        send_mail('Your login code', f'Your code is {code}', settings.DEFAULT_FROM_EMAIL, [user.email])
        increment_throttle('email_otp', ident); request.session['lost_phone_user_pk'] = user.pk
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'success': True, 'redirect': '/accounts/lost_phone/verify/'})
        return redirect('accounts:lost_phone_verify')

class LostPhoneVerifyView(View):
    def get(self, request):
        form = OTPVerifyForm(); return render(request, 'accounts/lost_phone_verify.html', {'form': form})
 
    def post(self, request):
        form = OTPVerifyForm(request.POST)
        if not form.is_valid():
            return render(request, 'accounts/lost_phone_verify.html', {'form': form})
        pk = request.session.get('lost_phone_user_pk')
        if not pk:
            messages.error(request, 'Session expired')
            return redirect('accounts:lost_phone_start')
        user = User.objects.get(pk=pk)
        code = form.cleaned_data['otp']
        key = f'otp:email:{user.pk}'
        if verify_otp(key, code):
            from django.contrib.auth import get_backends
            backend = get_backends()[0]
            backend_str = f"{backend.__module__}.{backend.__class__.__name__}"

            login(request, user, backend=backend_str)
            # Set session expiry similarly to TOTP flow: respect 'remember' or mobile flag
            try:
                mobile_flag = request.POST.get('remember') == '1' or request.headers.get('X-Mobile-Client') == '1' or request.GET.get('mobile') == '1'
                if mobile_flag:
                    request.session['mobile_client'] = True
                    request.session.set_expiry(getattr(settings, 'MOBILE_SESSION_TIMEOUT', 60 * 60 * 24 * 30))
                else:
                    request.session.set_expiry(getattr(settings, 'WEB_SESSION_IDLE_TIMEOUT', 20 * 60))
            except Exception:
                logger.exception('Failed to set session expiry for lost-phone login user %s', getattr(user,'pk',None))
            request.session['twofa_verified'] = True
            messages.success(request, 'Logged in via email fallback')
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': True, 'redirect': '/dashboard/'})
            return redirect('accounts:dashboard_home')
        else:
            messages.error(request, 'Invalid or expired code')
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': False, 'error': 'Invalid or expired code'}, status=400)
            return render(request, 'accounts/lost_phone_verify.html', {'form': form})

class SendOTPView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            phone = data.get("phone")
            if not phone:
                return JsonResponse({"success": False, "error": "Phone number is required"})
            
            # Simple rate limiting (3 attempts per hour per phone)
            cache_key = f"otp_attempts_{phone}"
            attempts = cache.get(cache_key, 0)
            
            if attempts >= 3:
                return JsonResponse({"success": False, "error": "Too many attempts. Please try again in an hour."})
            
            # Check if recently sent (5 minute cooldown)
            last_sent_key = f"otp_last_sent_{phone}"
            last_sent = cache.get(last_sent_key)
            
            if last_sent and (time.time() - last_sent) < 300:  # 5 minutes
                remaining = int(300 - (time.time() - last_sent))
                return JsonResponse({"success": False, "error": f"Please wait {remaining} seconds before requesting another OTP"})
            
            otp = str(random.randint(100000, 999999))  # 6-digit OTP

            service = EgoSMSService()
            sent = service.send_otp(phone, otp)

            if sent:
                # Store in session for verification
                request.session["otp_code"] = otp
                request.session["otp_phone"] = phone

                # Update rate limiting
                cache.set(cache_key, attempts + 1, 3600)  # 1 hour expiry
                cache.set(last_sent_key, time.time(), 300)  # 5 minute expiry

                return JsonResponse({"success": True})

            # If external provider failed, provide a safe dev fallback when credentials are missing
            missing_creds = not service.username or not service.password
            if missing_creds or getattr(settings, 'DEBUG', False):
                logger.warning("EgoSMS send failed but falling back to session-only OTP (dev). missing_creds=%s DEBUG=%s", missing_creds, getattr(settings, 'DEBUG', False))
                request.session["otp_code"] = otp
                request.session["otp_phone"] = phone
                cache.set(cache_key, attempts + 1, 3600)
                cache.set(last_sent_key, time.time(), 300)
                return JsonResponse({"success": True, "dev": True})

            # Real failure in production — log for investigation and return generic error
            logger.error("Failed to send OTP via EgoSMS for %s; username_present=%s", phone, bool(service.username))
            return JsonResponse({"success": False, "error": "Failed to send OTP. Please try again."})
                
        except Exception as e:
            # Log the actual error but don't expose it to users. Use module-level logger.
            logger.error("Error sending OTP: %s", str(e), exc_info=True)
            return JsonResponse({"success": False, "error": "An unexpected error occurred"})
              
class VerifyOTPView(View):
    def post(self, request):
        data = json.loads(request.body)
        otp = data.get("otp")
        phone = data.get("phone")

        if request.session.get("otp_code") == otp and request.session.get("otp_phone") == phone:
            # ✅ Mark OTP as verified
            request.session["otp_verified"] = True
            return JsonResponse({"success": True})

        return JsonResponse({"success": False, "error": "OTP does not match"})
          
@method_decorator(login_required, name='dispatch')
class ProfileTotpWizardView(View):
    """
    Step 1: Profile form (ProfileForm)
    Step 2: TOTP setup (QR + TOTPForm)
    Step 3: Success page
    """
    template_name = 'accounts/profile_totp_wizard.html'

    def _qr_for_secret(self, user, secret):
        issuer = os.getenv('PROJECT_NAME', 'BIM')
        otpauth = pyotp.totp.TOTP(secret).provisioning_uri(
            name=str(user.phone_number),
            issuer_name=issuer
        )
        img = qrcode.make(otpauth)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        return qr_b64

    def get(self, request, step="1"):
        user = request.user
        step = str(step)
        ctx = {
            "current_step": step,
            "totp_already": bool(user.totp_confirmed and user.totp_secret),
        }

        if step == "1":
            form = ProfileForm(instance=user)
            ctx["form"] = form
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'current_step': step, 'totp_already': ctx['totp_already']})
            return render(request, self.template_name, ctx)

        elif step == "2":
            if user.totp_confirmed and user.totp_secret:
                # Already configured → show "continue" message
                return render(request, self.template_name, ctx)

            # Generate or reuse secret in session
            secret = request.session.get('totp_setup_secret')
            if not secret:
                secret = pyotp.random_base32()
                request.session['totp_setup_secret'] = secret

            qr_b64 = self._qr_for_secret(user, secret)
            ctx.update({
                "qr_b64": qr_b64,
                "secret": secret,
                "totp_form": TOTPForm(),
            })
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'current_step': step, 'qr_b64': qr_b64, 'secret': secret})
            return render(request, self.template_name, ctx)

        elif step == "3":
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'current_step': step, 'totp_already': ctx['totp_already']})
            return render(request, self.template_name, ctx)

        # Fallback
        return redirect('accounts:profile_wizard', step='1')

    def post(self, request, step="1"):
        user = request.user
        step = str(step)

        if step == "1":
            # Save profile
            form = ProfileForm(request.POST, instance=user)
            if form.is_valid():
                form.save()
                messages.success(request, 'Profile saved.')
                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({'success': True, 'redirect': '/accounts/profile_wizard/2'})
                return redirect('accounts:profile_wizard', step='2')
            # Invalid → re-render step 1
            ctx = {"current_step": "1", "form": form, "totp_already": bool(user.totp_confirmed and user.totp_secret)}
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': False, 'errors': form.errors}, status=400)
            return render(request, self.template_name, ctx)

        elif step == "2":
            if user.totp_confirmed and user.totp_secret:
                # Nothing to do; go to success
                return redirect('accounts:profile_wizard', step='3')

            form = TOTPForm(request.POST)
            secret = request.session.get('totp_setup_secret')
            if not secret:
                messages.error(request, 'No TOTP session found. Please restart setup.')
                return redirect('accounts:profile_wizard', step='2')

            if form.is_valid():
                code = form.cleaned_data['code']
                totp = pyotp.TOTP(secret)
                if totp.verify(code):
                    user.totp_secret = secret
                    user.totp_confirmed = True
                    user.save()

                    request.session['twofa_verified'] = True
                    request.session.pop('totp_setup_secret', None)

                    messages.success(request, 'Authenticator setup complete.')
                    if request.headers.get('Accept') == 'application/json':
                        return JsonResponse({'success': True, 'redirect': '/accounts/profile_wizard/3'})
                    return redirect('accounts:profile_wizard', step='3')
                else:
                    messages.error(request, 'Invalid code. Please try again.')

            # If invalid, re-generate QR to display again
            qr_b64 = self._qr_for_secret(user, secret)
            ctx = {
                "current_step": "2",
                "qr_b64": qr_b64,
                "secret": secret,
                "totp_form": form,
                "totp_already": False,
            }
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': False, 'qr_b64': qr_b64})
            return render(request, self.template_name, ctx)

        elif step == "3":
            # Final CTA
            return redirect('accounts:dashboard_home')

        return redirect('accounts:profile_wizard', step='1')

from django.contrib.auth.decorators import login_required

@login_required
def throttle_status(request):
    ident = f'email:{request.user.email}'; secs = seconds_until_available('email_otp', ident)
    return JsonResponse({'email_otp_seconds': secs})

@login_required
@require_totp_setup
def dashboard_index(request):
    user = request.user
    today = timezone.now().date()
    start_of_week = today - timezone.timedelta(days=today.weekday())
    end_of_week = start_of_week + timezone.timedelta(days=6)
    start_of_month = today.replace(day=1)
    end_of_month = (start_of_month + timezone.timedelta(days=32)).replace(day=1) - timezone.timedelta(days=1)

    today_users = VoucherUser.objects.filter(created_at__date=today).count()
    week_users = VoucherUser.objects.filter(created_at__date__gte=start_of_week, created_at__date__lte=end_of_week).count()
    month_users = VoucherUser.objects.filter(created_at__date__gte=start_of_month, created_at__date__lte=end_of_month).count()

    recent_transactions = Transaction.objects.filter(router__user=user).select_related('router').order_by('-created_at')[:5]
    today_transactions = Transaction.objects.filter(created_at__date=today, router__user=user).aggregate(total=Sum('amount'))['total'] or 0
    week_transactions = Transaction.objects.filter(created_at__date__gte=start_of_week, created_at__date__lte=end_of_week, router__user=user).aggregate(total=Sum('amount'))['total'] or 0
    month_transactions = Transaction.objects.filter(created_at__date__gte=start_of_month, created_at__date__lte=end_of_month, router__user=user).aggregate(total=Sum('amount'))['total'] or 0

    # Build chart data in Python to avoid backend-specific SQL functions
    start_chart = today - timezone.timedelta(days=6)
    txs = Transaction.objects.filter(router__user=user, created_at__date__gte=start_chart).values('created_at', 'amount')
    from collections import defaultdict
    from decimal import Decimal
    daily = defaultdict(Decimal)
    for t in txs:
        dt = t['created_at']
        if not dt:
            continue
        d = dt.date() if hasattr(dt, 'date') else dt
        daily[d] += Decimal(t['amount'] or 0)

    chart_data = []
    for i in range(7):
        d = today - timezone.timedelta(days=i)
        chart_data.append({'date': d, 'total': daily.get(d, Decimal('0.00'))})

    router_balances = Router.objects.filter(user=user).annotate(
        transactions_total=Sum('transactions__amount')
    )

    data = {
        'recentTransactions': list(recent_transactions.values()),
        'todayTransactions': today_transactions,
        'weekTransactions': week_transactions,
        'monthTransactions': month_transactions,
        'routerBalances': list(router_balances.values()),
        'todayUsers': today_users,
        'weekUsers': week_users,
        'monthUsers': month_users,
        'chartData': chart_data,
    }

    if request.headers.get('Accept') == 'application/json':
        return JsonResponse(data)
    return render(request, 'dashboard.html', data)


@login_required
def access_redirect(request):
    """Redirect helper: send user to their account's access management page.

    Finds an Account where the user is owner first, else uses the first membership's account.
    """
    try:
        # Prefer account owned by the user
        acct = Account.objects.filter(owner=request.user).first()
        if not acct:
            membership = AccountMembership.objects.filter(user=request.user).select_related('account').first()
            acct = membership.account if membership else None
        if not acct:
            messages.error(request, 'No account found to manage. Create an account first.')
            return redirect('accounts:dashboard_home')
        return redirect('accounts:access_management', account_id=acct.id)
    except Exception:
        logger.exception('Failed to redirect to access management for user %s', request.user.id)
        messages.error(request, 'Could not open Access Management. Please try again.')
        return redirect('accounts:dashboard_home')


@login_required
def access_management(request, account_id):
    """Render the Access Management UI for an account."""
    account = get_object_or_404(Account, id=account_id)
    # Only owner or staff can view access management
    if account.owner_id != request.user.id and not request.user.is_staff:
        messages.error(request, 'Only the account owner may manage access.')
        return redirect('accounts:dashboard_home')

    # Ensure the owner appears as a membership
    try:
        owner_exists = AccountMembership.objects.filter(account=account, role='owner', user=account.owner).exists()
    except Exception:
        owner_exists = False

    if not owner_exists:
        try:
            AccountMembership.objects.create(
                user=account.owner,
                account=account,
                role='owner',
                invited_by=account.owner,
                invitation_email=account.owner.email or '',
                accepted=True,
            )
        except Exception:
            logger.exception('Failed to ensure owner membership for account %s', account.id)

    memberships = AccountMembership.objects.filter(account=account).select_related('user').order_by('-accepted', 'role')
    role_choices = getattr(AccountMembership, 'ROLE_CHOICES', [])
    return render(request, 'accounts/access_management.html', {'account': account, 'memberships': memberships, 'role_choices': role_choices})


@login_required
def cancel_invitation(request, membership_id):
    """Cancel a pending AccountMembership invitation.

    - Only the account owner (or staff) may cancel an invitation for that account.
    - Only pending (accepted=False) invitations are deletable.
    - Supports JSON responses when the client requests application/json or X-Requested-With=XMLHttpRequest.
    """
    try:
        membership = get_object_or_404(AccountMembership, id=membership_id)
        account = membership.account

        # Authorization: only account owner or staff may cancel
        if account.owner_id != request.user.id and not request.user.is_staff:
            messages.error(request, 'Only the account owner may cancel invitations.')
            if request.headers.get('Accept') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': 'forbidden'}, status=403)
            return redirect('accounts:access_management', account_id=account.id)

        if request.method != 'POST':
            # We expect a POST from the confirmation form. Redirect back otherwise.
            return redirect('accounts:access_management', account_id=account.id)

        if membership.accepted:
            messages.error(request, 'Cannot cancel a membership that has already been accepted.')
            if request.headers.get('Accept') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': 'already_accepted'}, status=400)
            return redirect('accounts:access_management', account_id=account.id)

        # Delete the pending invitation
        try:
            membership.delete()
            # Don't add a Django success message here; the client shows inline feedback.
            logger.info('Invitation cancelled: membership %s by user %s', membership_id, getattr(request.user, 'pk', None))
            if request.headers.get('Accept') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': True})
            return redirect('accounts:access_management', account_id=account.id)
        except Exception:
            logger.exception('Failed to delete invitation %s', membership_id)
            messages.error(request, 'Failed to cancel invitation. Please try again.')
            if request.headers.get('Accept') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': 'delete_failed'}, status=500)
            return redirect('accounts:access_management', account_id=account.id)

    except AccountMembership.DoesNotExist:
        if request.headers.get('Accept') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'error': 'not_found'}, status=404)
        messages.error(request, 'Invitation not found.')
        return redirect('accounts:dashboard_home')

# ====================
# End Dashboard Views Block
# ====================

def map_sumsub_status(payload):
    review_status = payload.get("reviewStatus")
    review_result = payload.get("reviewResult", {}).get("reviewAnswer")

    if review_status == "pending":
        return "pending"
    if review_status == "completed":
        if review_result == "GREEN":
            return "approved"
        elif review_result == "RED":
            return "rejected"
        elif review_result == "GRAY":
            return "review"
    return "unknown"

@csrf_exempt
def sumsub_webhook(request):
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    # Map externalUserId → your User
    external_user_id = data.get("externalUserId")
    try:
        user = User.objects.get(pk=external_user_id)
    except User.DoesNotExist:
        return JsonResponse({"error": f"User {external_user_id} not found"}, status=404)

    # Extract review answer if present
    review_answer = None
    if "reviewResult" in data and isinstance(data["reviewResult"], dict):
        review_answer = data["reviewResult"].get("reviewAnswer")

    # 1. Store raw webhook event (audit log)
    KYCResult.objects.create(
        user=user,
        applicant_id=data.get("applicantId"),
        inspection_id=data.get("inspectionId"),
        correlation_id=data.get("correlationId"),
        level_name=data.get("levelName"),
        event_type=data.get("type"),
        review_status=data.get("reviewStatus"),
        review_answer=review_answer,
        raw_payload=data,
    )

    # 2. Normalize status and update/create latest snapshot
    normalized_status = map_sumsub_status(data)
    KYC.objects.update_or_create(
        user=user,
        defaults={
            "provider": "sumsub",
            "external_id": data.get("applicantId") or data.get("inspectionId"),
            "status": normalized_status,
            "raw_response": data,
        },
    )

    return JsonResponse({"status": "ok"})
    
def kyc_results_list(request):
    results = KYCResult.objects.select_related("user").order_by("-created_at")
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({'results': [
            {'id': r.id, 'user_id': str(r.user_id), 'status': r.review_status, 'created_at': r.created_at.isoformat()} for r in results
        ]})
    return render(request, "accounts/kyc_results_list.html", {"results": results})
    
@login_required
def logout_view(request):
    logout(request)
    #messages.success(request, "You have been logged out.")
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({'success': True, 'redirect': '/'})
    return redirect("/")
