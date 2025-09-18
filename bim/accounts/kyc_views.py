from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse, HttpResponseForbidden
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse
from .models import KYC
from .kyc_providers import sumsub_generate_sdk_token, sumsub_verify_webhook, veriff_create_session, veriff_verify_webhook
import json, qrcode, io, base64, logging

logger = logging.getLogger(__name__)

@login_required
def kyc_start(request):
    user = request.user
    provider = request.GET.get('provider', 'sumsub').lower()
    # Default verification link (kept for backward compatibility)
    verification_link = "https://in.sumsub.com/websdk/p/sbx_i5gpC4AtwlVgN0Nk"

    # Provider-specific data (populated below when available)
    sdk_token = None
    veriff_link = None

    # Create or get KYC record
    kyc, created = KYC.objects.get_or_create(user=user, defaults={'provider': provider, 'status': 'pending'})

    # Detect mobile early (used by short-circuit branches)
    user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
    is_mobile = 'mobile' in user_agent

    # Decide if the user already submitted documents (even if not yet approved).
    # We treat records produced by external providers or explicit user status as
    # "submitted". However, a freshly-created placeholder KYC row (status
    # 'pending' but without an external_id) should not be treated as a real
    # submission — that case is often created by internal housekeeping and
    # would confuse users by saying "already submitted" when they haven't.
    user_kyc_status = getattr(user, 'kyc_status', None)
    kyc_status_value = (getattr(kyc, 'status', None) or user_kyc_status or '').lower()
    # States that indicate a genuine submission or provider result. Exclude
    # bare 'pending' here so we can special-case placeholder rows below.
    submitted_states = {'submitted', 'in_review', 'processing', 'approved', 'completed'}
    has_external = bool(getattr(kyc, 'external_id', None))
    # If the KYC status is 'pending' but there's no external_id and the user's
    # kyc_status is still the default/empty, treat this as a placeholder and
    # not as a real submission.
    placeholder_pending = (kyc_status_value == 'pending' and not has_external and (not user_kyc_status or str(user_kyc_status).lower() in ('none', '')))
    is_submitted = (not created) and (has_external or (kyc_status_value in submitted_states and not placeholder_pending) or (str(user_kyc_status or '').lower() in submitted_states))

    # If the user has already been approved/verified, return that first
    if kyc_status_value in ('approved', 'completed'):
        ctx = {
            'already_verified': True,
            'kyc_status': kyc_status_value,
            'provider': kyc.provider if getattr(kyc, 'provider', None) else provider,
            'external_id': getattr(kyc, 'external_id', None),
            'updated_at': getattr(kyc, 'updated_at', None),
        }
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'already_verified': True, 'kyc_status': kyc_status_value, 'provider': ctx['provider'], 'external_id': ctx['external_id']})
        if is_mobile:
            return render(request, 'kyc/start_mobile.html', ctx)
        return render(request, 'kyc/start.html', ctx)

    # If the user already submitted documents (even if still pending/review), don't re-run provider flows
    if is_submitted:
        ctx = {
            'already_submitted': True,
            'kyc_status': kyc_status_value,
            'provider': kyc.provider if getattr(kyc, 'provider', None) else provider,
            'external_id': getattr(kyc, 'external_id', None),
            'updated_at': getattr(kyc, 'updated_at', None),
        }
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'already_submitted': True, 'kyc_status': kyc_status_value, 'provider': ctx['provider'], 'external_id': ctx['external_id']})
        if is_mobile:
            return render(request, 'kyc/start_mobile.html', ctx)
        return render(request, 'kyc/start.html', ctx)

    # Build payload for both HTML and JSON
    qr_b64 = None
    if not is_mobile:
        qr_img = qrcode.make(verification_link)
        buf = io.BytesIO()
        qr_img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

    # Provider integrations: try to generate SDK token / session when requested
    try:
        if provider == 'sumsub':
            try:
                # supply user id and contact hints if available
                email = getattr(user, 'email', None)
                phone = getattr(user, 'phone_number', None) if hasattr(user, 'phone_number') else None
                token_resp = sumsub_generate_sdk_token(str(user.pk), email=email, phone=phone)
                # token_resp shape varies; try common keys
                if isinstance(token_resp, dict):
                    sdk_token = token_resp.get('token') or token_resp.get('accessToken') or token_resp.get('sdkToken') or token_resp.get('access_token') or token_resp.get('tokenValue')
                else:
                    sdk_token = token_resp
            except Exception as e:
                logger.exception('Failed to generate Sumsub SDK token')
                sdk_token = None
        elif provider == 'veriff':
            try:
                callback = request.build_absolute_uri(reverse('accounts:kyc_webhook_veriff'))
                session = veriff_create_session(str(user.pk), getattr(user, 'first_name', None), getattr(user, 'last_name', None), callback_url=callback)
                # session payload shapes vary by vendor
                if isinstance(session, dict):
                    veriff_link = (session.get('verification') or {}).get('url') or session.get('url') or session.get('verificationUrl') or session.get('sessionUrl')
                    # some APIs return a 'session' or 'token' to be embedded in an iframe
                else:
                    veriff_link = None
            except Exception:
                logger.exception('Failed to create Veriff session')
                veriff_link = None
    except Exception:
        # Catch-all safe guard so template rendering isn't blocked by provider failures
        logger.exception('Unexpected error in KYC provider integration')

    # If API client requested JSON, return JSON payload
    if request.headers.get('Accept') == 'application/json':
        payload = {
            'verification_link': verification_link,
            'mobile': is_mobile,
            'provider': provider,
        }
        if qr_b64:
            payload['qr_code'] = qr_b64
        if sdk_token:
            payload['sdk_token'] = sdk_token
        if veriff_link:
            payload['veriff_link'] = veriff_link
        return JsonResponse(payload)

    # Default: render HTML templates
    if is_mobile:
        # Mobile template primarily needs a verification link or session token
        ctx = {'verification_link': veriff_link or verification_link, 'provider': provider}
        if sdk_token:
            ctx['sdk_token'] = sdk_token
        return render(request, 'kyc/start_mobile.html', ctx)

    # Desktop: provide QR and provider-specific tokens/links to the template
    ctx = {'qr_code': qr_b64, 'verification_link': veriff_link or verification_link, 'provider': provider}
    if sdk_token:
        ctx['sdk_token'] = sdk_token
    return render(request, 'kyc/start.html', ctx)


@csrf_exempt
def kyc_webhook_sumsub(request):
    raw = request.body; headers = request.headers
    ok = sumsub_verify_webhook(raw, headers)
    if not ok: return HttpResponseForbidden('invalid signature')
    payload = json.loads(raw.decode('utf-8') or '{}')
    applicant_id = payload.get('applicantId') or payload.get('applicant_id') or payload.get('id')
    k = KYC.objects.filter(external_id=applicant_id).first()
    if not k: return HttpResponse(status=404)
    status = payload.get('reviewStatus') or payload.get('status') or payload.get('result')
    if status and status.lower() in ('approved','accept','clear','green'):
        k.status = 'approved'; k.user.kyc_status = 'approved'
    elif status and status.lower() in ('rejected','denied','red','failed'):
        k.status = 'rejected'; k.user.kyc_status = 'rejected'
    else:
        k.status = 'pending'; k.user.kyc_status = 'pending'
    k.raw_response = payload; k.save(); k.user.save(); return HttpResponse('ok')

@csrf_exempt
def kyc_webhook_veriff(request):
    raw = request.body; headers = request.headers
    ok = veriff_verify_webhook(raw, headers)
    if not ok: return HttpResponseForbidden('invalid signature')
    payload = json.loads(raw.decode('utf-8') or '{}')
    vid = None
    if isinstance(payload, dict):
        if 'verification' in payload:
            vid = payload['verification'].get('id') or payload.get('id')
        else:
            vid = payload.get('id') or payload.get('verificationId') or payload.get('sessionId')
    if not vid:
        vendor = payload.get('vendorData') or payload.get('endUserId')
        if vendor:
            k = KYC.objects.filter(user__pk=vendor).order_by('-created_at').first()
        else:
            k = None
    else:
        k = KYC.objects.filter(external_id=vid).first()
    if not k: return HttpResponse(status=404)
    status = payload.get('status') or (payload.get('verification') or {}).get('status') or payload.get('action')
    if status and str(status).lower() in ('approved','success','clear'):
        k.status = 'approved'; k.user.kyc_status = 'approved'
    elif status and str(status).lower() in ('rejected','fail','declined','denied'):
        k.status = 'rejected'; k.user.kyc_status = 'rejected'
    else:
        k.status = 'pending'; k.user.kyc_status = 'pending'
    k.raw_response = payload; k.save(); k.user.save(); return HttpResponse('ok')
