from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator
from .forms import RouterForm
from django.contrib.auth.decorators import login_required
from accounts.decorators import require_totp_setup
from django.contrib import messages
from .models import Router
from routeros_api import RouterOsApiPool
import datetime
import logging
import time
import re
import qrcode
from io import BytesIO
from django.core.files.base import ContentFile
from django.utils import timezone
from .models import VoucherUser, Transaction
from django.db.models import Sum, Count, F
from django.db import transaction as db_transaction
from django.db.models.functions import TruncDate
import random
import logging
from django.views.decorators.http import require_POST
import pandas as pd
from django.utils.dateparse import parse_date
from django.template.loader import render_to_string
from xhtml2pdf import pisa
from django.core.mail import send_mail
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.conf import settings
import json
from django.contrib.staticfiles import finders
from django.http import FileResponse, HttpResponseNotFound
from django.urls import reverse
from urllib.parse import quote

def home(request):
    # Provide timestamp and simple captcha values for the contact form
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    ctx = {
        'timestamp': int(time.time()),
        'captcha_a': a,
        'captcha_b': b,
    }
    return render(request, 'welcome.html', ctx)


@require_POST
def contact_submit(request):
    """AJAX endpoint for contact form. Expects form-encoded POST with CSRF token.

    Security: honeypot 'website' field, timestamp freshness, simple math captcha (field 'captcha'),
    and rate limiting per IP (60s cooldown).
    """
    # Basic rate limiting by IP
    ip = request.META.get('REMOTE_ADDR', 'unknown')
    key = f'contact_rate_{ip}'
    if cache.get(key):
        return JsonResponse({'success': False, 'error': 'Too many requests. Please wait a moment.'}, status=429)

    # Parse data (support JSON or form-encoded)
    if request.content_type == 'application/json':
        try:
            data = json.loads(request.body.decode())
        except Exception:
            return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    else:
        data = request.POST

    # Honeypot
    if data.get('website'):
        return JsonResponse({'success': False, 'error': 'Spam detected'}, status=400)

    # Timestamp freshness (allow 1 hour)
    try:
        ts = float(data.get('timestamp') or 0)
        import time
        if abs(time.time() - ts) > 3600:
            return JsonResponse({'success': False, 'error': 'Form expired. Please refresh the page.'}, status=400)
    except Exception:
        pass

    # Simple math captcha: the template should include inputs 'captcha_a' and 'captcha_b' and 'captcha'
    try:
        a = int(data.get('captcha_a') or 0)
        b = int(data.get('captcha_b') or 0)
        expected = a + b
        if int(data.get('captcha') or -999) != expected:
            return JsonResponse({'success': False, 'error': 'Captcha incorrect'}, status=400)
    except Exception:
        return JsonResponse({'success': False, 'error': 'Captcha validation failed'}, status=400)

    name = data.get('name')
    email = data.get('email')
    message = data.get('message')

    if not (name and email and message):
        return JsonResponse({'success': False, 'error': 'Missing required fields'}, status=400)

    # Compose and send email
    subject = f'Contact form message from {name}'
    body = render_to_string('emails/contact_email.txt', {'name': name, 'email': email, 'message': message})
    recipient = getattr(settings, 'CONTACT_EMAIL', None) or settings.DEFAULT_FROM_EMAIL

    try:
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [recipient], fail_silently=False)
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Failed to send email: {str(e)}'}, status=500)

    # Set rate limit key for 60 seconds
    cache.set(key, True, 60)

    return JsonResponse({'success': True, 'message': 'Message sent. We will get back to you shortly.'})


def routers_json(request, filename):
    """Serve static json files requested at /routers/json/<filename> as a fallback for legacy frontend paths."""
    # Normalize filename to avoid directory traversal
    filename = filename.lstrip('/')
    # Look for the file in common static json locations
    candidates = [f'json/{filename}', f'json/locales/{filename}']
    for candidate in candidates:
        path = finders.find(candidate)
        if path:
            if candidate.endswith('.json'):
                try:
                    return FileResponse(open(path, 'rb'), content_type='application/json')
                except Exception:
                    return HttpResponseNotFound()
            else:
                try:
                    return FileResponse(open(path, 'rb'))
                except Exception:
                    return HttpResponseNotFound()
    return HttpResponseNotFound()

# Router Views Block
# Converted from Laravel RouterController
# ====================

# 1. Utility: Initialize RouterOS API client

def initialize_client(router):
    """Create and verify a RouterOsApiPool for the given Router.

    Behavior:
    - If the Router model exposes an `api_port` or `port` attribute, try that first.
    - Otherwise try plaintext on 8729 then 8728 (many devices use 8729 for API but without TLS in some setups).
    - Use plaintext login to match devices that expect plain username/password exchange.
    - Perform a light login check (call .get_api()) so callers receive a usable pool or a clear error.
    """
    host = getattr(router, 'ip_address', None)
    username = getattr(router, 'router_user', None)
    password = getattr(router, 'router_password', None)

    configured_port = getattr(router, 'api_port', None) or getattr(router, 'port', None)
    candidate_ports = []
    if configured_port:
        try:
            candidate_ports.append(int(configured_port))
        except Exception:
            logging.getLogger(__name__).warning('Configured router port is not an int: %r', configured_port)
    # prefer 8728 then 8729 when no explicit port configured
    for p in (8728, 8729):
        if p not in candidate_ports:
            candidate_ports.append(p)

    last_exc = None
    for port in candidate_ports:
        # try plaintext login first (some setups expect plaintext on these ports), then challenge-response
        for plaintext_flag in (True, False):
            api_pool = None
            try:
                logging.getLogger(__name__).info('initialize_client attempting %s:%s plaintext_login=%s', host, port, plaintext_flag)
                api_pool = RouterOsApiPool(
                    host=host,
                    username=username,
                    password=password,
                    port=port,
                    use_ssl=False,
                    plaintext_login=plaintext_flag,
                )
                # quick verification: attempt to get an API instance (this performs login)
                api = api_pool.get_api()
                logging.getLogger(__name__).info('initialize_client succeeded for %s:%s plaintext_login=%s', host, port, plaintext_flag)
                return api_pool
            except Exception as e:
                logging.getLogger(__name__).warning(
                    'initialize_client failed for %s:%s plaintext_login=%s -> %r',
                    host,
                    port,
                    plaintext_flag,
                    e,
                )
                last_exc = e
                try:
                    if api_pool is not None:
                        api_pool.disconnect()
                except Exception:
                    pass

    raise RuntimeError(
        f'Failed to connect to router {getattr(router, "id", "?")} at {host} on ports {candidate_ports}: {repr(last_exc)}'
    )


def _normalize_routeros_dict(d):
    """Return a shallow copy of dict `d` with keys normalized for templates.

    RouterOS returns keys with hyphens like 'free-memory' which are not
    valid attribute lookups in Django templates (they get parsed as
    subtraction). Replace '-' with '_' in keys so templates can use
    dot-notation (e.g. sys.free_memory).
    """
    if not isinstance(d, dict):
        return d
    return {k.replace('-', '_'): v for k, v in d.items()}


def resolve_router_profile_name(api, token):
    """Given an API instance and a token (either a slug the user typed, or a router-side profile name),
    return the canonical router profile name (e.g. 'profile_5HRS500shs-se:...').

    Behavior:
    - If token looks like an existing router profile name (starts with 'profile_'), return it.
    - Otherwise, fetch all profiles and match by the display slug computed by stripping 'profile_' and trailing suffixes.
    - If no match, return None.
    """
    if not token:
        return None
    # if user already supplied full router name, return as-is
    if isinstance(token, str) and token.startswith('profile_'):
        return token

    try:
        resource = api.get_resource('/ip/hotspot/user/profile')
        profiles = resource.get()
        try:
            profiles = list(profiles)
        except Exception:
            pass
    except Exception:
        return None

    # Normalize matching token
    token_norm = str(token).strip()
    for p in profiles:
        raw = p.get('name', '') or ''
        if not raw:
            continue
        if raw.startswith('profile_'):
            s = raw[len('profile_'):]
            idx = s.find('-se')
            display = s[:idx].strip() if idx != -1 else s.strip()
        else:
            display = raw

        if display == token_norm or raw == token_norm:
            return raw

    return None

# 2. List routers (index)
@login_required
def router_index(request):
    routers = Router.objects.filter(user=request.user).order_by('-created_at')
    paginator = Paginator(routers, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    context = {
        'routers': page_obj,
        'page_obj': page_obj,
        'paginator': paginator
    }
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({'routers': list(page_obj.object_list.values()), 'message': 'Routers retrieved successfully', 'page': page_obj.number, 'num_pages': paginator.num_pages})
    return render(request, 'routers/index.html', context)

# 3. Show form for creating router (create)
@login_required
def router_create(request):
    form = RouterForm()
    return render(request, 'routers/create.html', {'form': form})

# 4. Store new router (store)
@login_required
def router_store(request):
    if request.method == 'POST':
        form = RouterForm(request.POST)
        if form.is_valid():
            router = form.save(commit=False)
            router.user = request.user
            router.save()
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'router': {
                    'id': str(router.id),
                    'name': router.name,
                    'location': router.location,
                    'type': router.type,
                    'ip_address': router.ip_address,
                    'router_user': router.router_user,
                    'router_password': router.router_password,
                }, 'message': 'Router created successfully'}, status=201)
            messages.success(request, 'Router created successfully.')
            return redirect('routers.index')
        else:
            # Improved error handling: log validation errors and surface them
            errors = {field: list(errs) for field, errs in form.errors.items()}
            logging.getLogger(__name__).warning('Router create failed: user=%s post=%s errors=%s', request.user, dict(request.POST), errors)
            # If client expects JSON, return structured errors with 400
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'errors': errors, 'message': 'Validation failed'}, status=400)

            # For HTML responses, show detailed message to the user and render form with errors
            # Flatten error messages for a readable flash message
            flat = []
            for e in errors.values():
                flat.extend(e)
            messages.error(request, 'Failed to create router: ' + '; '.join(flat))
    else:
        form = RouterForm()
    return render(request, 'routers/create.html', {'form': form})

# 5. Display specified router (show)
@login_required
def router_show(request, router_id):
    router = get_object_or_404(Router, pk=router_id, user=request.user)
    # Try to fetch live data from the RouterOS device. If it fails, fall back to DB fields.
    live = None
    live_error = None
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        # Minimal live info: system resource and interface summary
        sys_res = api.get_resource('/system/resource').get()
        # ensure we return plain python structures (TypedPromiseDecorator returns a promise-like)
        try:
            sys_res = list(sys_res)
        except Exception:
            # keep as-is if not iterable
            pass
        interfaces = api.get_resource('/interface').get()
        try:
            interfaces = list(interfaces)
        except Exception:
            pass
        api_pool.disconnect()
        # Normalize keys for template-friendly access
        try:
            norm_sys = [ _normalize_routeros_dict(s) for s in list(sys_res) ] if hasattr(sys_res, '__iter__') else _normalize_routeros_dict(sys_res)
        except Exception:
            norm_sys = sys_res
        # convert memory byte values to MB for nicer display
        try:
            if isinstance(norm_sys, list):
                for s in norm_sys:
                    try:
                        fm = s.get('free_memory') or s.get('free_memory')
                        tm = s.get('total_memory') or s.get('total_memory')
                        if fm is not None:
                            s['free_memory_mb'] = int(int(str(fm)) // (1024*1024))
                        if tm is not None:
                            s['total_memory_mb'] = int(int(str(tm)) // (1024*1024))
                    except Exception:
                        pass
            elif isinstance(norm_sys, dict):
                try:
                    fm = norm_sys.get('free_memory')
                    tm = norm_sys.get('total_memory')
                    if fm is not None:
                        norm_sys['free_memory_mb'] = int(int(str(fm)) // (1024*1024))
                    if tm is not None:
                        norm_sys['total_memory_mb'] = int(int(str(tm)) // (1024*1024))
                except Exception:
                    pass
        except Exception:
            pass
        try:
            norm_ifaces = [ _normalize_routeros_dict(i) for i in list(interfaces) ]
        except Exception:
            norm_ifaces = interfaces
        live = {
            'system': norm_sys,
            'interfaces': norm_ifaces,
        }
    except Exception as e:
        logging.getLogger(__name__).warning('Failed to fetch live router data for %s: %s', router_id, str(e))
        live_error = str(e)

    if request.headers.get('Accept') == 'application/json':
        payload = {
            'router': {
                'id': str(router.id),
                'name': router.name,
                'location': router.location,
                'type': router.type,
                'ip_address': router.ip_address,
                'router_user': router.router_user,
            },
            'live': live,
            'live_error': live_error,
        }
        return JsonResponse(payload)

    return render(request, 'routers/show.html', {'router': router, 'live': live, 'live_error': live_error})

# 6. Show form for editing router (edit)
@login_required
def router_edit(request, router_id):
    router = get_object_or_404(Router, pk=router_id, user=request.user)
    form = RouterForm(instance=router)
    return render(request, 'routers/edit.html', {'form': form, 'router': router})

# 7. Update router (update)
@login_required
def router_update(request, router_id):
    router = get_object_or_404(Router, pk=router_id, user=request.user)
    if request.method == 'POST':
        form = RouterForm(request.POST, instance=router)
        if form.is_valid():
            form.save()
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'router': {
                    'id': str(router.id),
                    'name': router.name,
                    'location': router.location,
                    'type': router.type,
                    'ip_address': router.ip_address,
                    'router_user': router.router_user,
                    'router_password': router.router_password,
                }, 'message': 'Router updated successfully'})
            messages.success(request, 'Router updated successfully.')
            return redirect('routers.index')
        else:
            errors = {field: list(errs) for field, errs in form.errors.items()}
            logging.getLogger(__name__).warning('Router update failed: user=%s router_id=%s post=%s errors=%s', request.user, router_id, dict(request.POST), errors)
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'errors': errors, 'message': 'Validation failed'}, status=400)
            flat = []
            for e in errors.values():
                flat.extend(e)
            messages.error(request, 'Failed to update router: ' + '; '.join(flat))
    form = RouterForm(instance=router)
    return render(request, 'routers/edit.html', {'form': form, 'router': router})

# 8. Delete router (destroy)
@login_required
def router_destroy(request, router_id):
    router = get_object_or_404(Router, pk=router_id, user=request.user)
    if request.method == 'POST':
        router.delete()
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'message': 'Router deleted successfully'})
        messages.success(request, 'Router deleted successfully.')
        return redirect('routers.index')
    messages.error(request, 'Delete must be POST.')
    return redirect('routers.index')

# 9. Connect to router (connectToRouter)
@login_required
@require_POST
def router_connect_to_router(request, router_id):
    """AJAX endpoint: attempt to connect to the RouterOS device and return JSON status.

    Uses the URL-provided router_id (so JS calls /routers/<router_id>/connect/).
    """
    router = get_object_or_404(Router, pk=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        # perform a lightweight health check
        sys_res = api.get_resource('/system/resource').get()
        try:
            sys_res = list(sys_res)
        except Exception:
            pass
        api_pool.disconnect()
        # normalize for JSON/template safety
        try:
            sys_norm = [ _normalize_routeros_dict(s) for s in list(sys_res) ] if hasattr(sys_res, '__iter__') else _normalize_routeros_dict(sys_res)
        except Exception:
            sys_norm = sys_res
        message = 'Connected to the router successfully.'
        payload = {'message': message, 'system': sys_norm}
        return JsonResponse(payload, status=200)
    except Exception as e:
        logging.getLogger(__name__).warning('Router connect failed: user=%s router_id=%s err=%s', request.user, router_id, str(e))
        message = f'Failed to connect to the router: {str(e)}'
        return JsonResponse({'error': message}, status=500)

# 10. Get router status (getRouterStatus)
@login_required
def router_get_status(request, router_id):
    router = get_object_or_404(Router, pk=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        status = api.get_resource('/system/resource').get()
        try:
            status = list(status)
        except Exception:
            pass
        api_pool.disconnect()
        try:
            status_norm = [ _normalize_routeros_dict(s) for s in list(status) ] if hasattr(status, '__iter__') else _normalize_routeros_dict(status)
        except Exception:
            status_norm = status
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'status': status_norm})
        return render(request, 'routers/show.html', {'router': router, 'status': status_norm})
    except Exception as e:
        message = f'Failed to retrieve router status: {str(e)}'
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'error': message}, status=500)
        messages.error(request, message)
    return redirect('routers.show', pk=router_id)

# 11. Ping router (pingRouter)
@login_required
def router_ping(request, router_id):
    router = get_object_or_404(Router, pk=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        # Use the 'ping' command and materialize results
        ping_result = api.get_resource('/tool/ping').call('ping', {'address': router.ip_address, 'count': 4}).get()
        try:
            ping_result = list(ping_result)
        except Exception:
            pass
        api_pool.disconnect()
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'message': 'Ping successful', 'ping_response': ping_result})
        return render(request, 'routers/show.html', {'router': router, 'ping_result': ping_result})
    except Exception as e:
        message = f'Ping failed: {str(e)}'
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'error': message}, status=500)
        messages.error(request, message)
    return redirect('routers.show', router_id=router_id)

# 12. List hotspots (listHotspots)
@login_required
def router_list_hotspots(request, router_id):
    router = get_object_or_404(Router, pk=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        hotspots = api.get_resource('/ip/hotspot').get()
        try:
            hotspots = list(hotspots)
        except Exception:
            pass
        api_pool.disconnect()
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'router': str(router.id), 'hotspots': hotspots, 'message': 'Hotspots retrieved successfully'})
        return render(request, 'routers/servers.html', {'router': router, 'hotspots': hotspots})
    except Exception as e:
        message = f'Failed to load hotspots: {str(e)}'
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'error': message}, status=500)
        messages.error(request, message)
    return redirect('routers.show', router_id=router_id)

# 13. List all hotspot servers with status (listAllHotspotServers)
@login_required
def router_list_all_hotspot_servers(request, router_id):
    router = get_object_or_404(Router, pk=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        hotspots = api.get_resource('/ip/hotspot').get()
        try:
            hotspots = list(hotspots)
        except Exception:
            pass
        status = api.get_resource('/system/resource').get()
        try:
            status = list(status)
        except Exception:
            pass
        api_pool.disconnect()
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'router': str(router.id), 'hotspots': hotspots, 'status': status, 'message': 'Hotspot data retrieved successfully'})
        return render(request, 'routers/servers.html', {'router': router, 'hotspots': hotspots, 'status': status})
    except Exception as e:
        message = f'Failed to fetch data: {str(e)}'
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'error': message}, status=500)
        messages.error(request, message)
    return redirect('routers.show', router_id=router_id)

# 14. Utility: Handle unauthorized access

def handle_unauthorized(request):
    message = 'Unauthorized action.'
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({'error': message}, status=403)
    return render(request, 'routers/index.html', {'error': message})

# 15. Utility: Handle error responses

def error_response(request, message, status=400):
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({'error': message}, status=status)
    return render(request, 'routers/index.html', {'error': message})

# ====================
# End Router Views Block
# ====================

# ====================
# Package Views Block
# Converted from Laravel PackageController
# ====================

@login_required
def package_list_routers(request):
    routers = Router.objects.filter(user=request.user).order_by('-created_at')
    paginator = Paginator(routers, 5)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({'routers': list(page_obj.object_list.values()), 'message': 'Routers retrieved successfully', 'page': page_obj.number, 'num_pages': paginator.num_pages})
    return render(request, 'packages/index.html', {'routers': page_obj})

@login_required
def package_list_all_hotspot_servers(request, router_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        hotspots = api.get_resource('/ip/hotspot').get()
        try:
            hotspots = list(hotspots)
        except Exception:
            pass
        api_pool.disconnect()
        return render(request, 'packages/hotspots.html', {'router': router, 'hotspots': hotspots})
    except Exception as e:
        messages.error(request, f'Failed to fetch hotspots: {str(e)}')
        return redirect('packages.index')

@login_required
def package_get_all_hotspot_user_profiles(request, router_id, hotspot_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        profiles = api.get_resource('/ip/hotspot/user/profile').get()
        try:
            profiles = list(profiles)
        except Exception:
            pass
        # Normalize profile dicts and compute display names so templates can use dot-notation
        norm_profiles = []
        for p in profiles:
            try:
                p_dict = p if isinstance(p, dict) else dict(p)
                p_norm = _normalize_routeros_dict(p_dict)
                raw = p_norm.get('name', '') or ''
                if raw.startswith('profile_'):
                    s = raw[len('profile_'):]
                    idx = s.find('-se')
                    display = s[:idx].strip() if idx != -1 else s.strip()
                else:
                    display = raw
                p_norm['display_name'] = display
                # Provide template-friendly aliases: bandwidth (rate-limit) and duration (keepalive-timeout)
                try:
                    # RouterOS uses hyphenated keys like 'rate-limit' which we normalized to 'rate_limit'
                    p_norm['bandwidth'] = p_norm.get('rate_limit')
                except Exception:
                    p_norm['bandwidth'] = None
                try:
                    p_norm['duration'] = p_norm.get('keepalive_timeout')
                except Exception:
                    p_norm['duration'] = None
                norm_profiles.append(p_norm)
            except Exception:
                try:
                    raw = p.get('name', '') or ''
                    display = raw
                    p['display_name'] = display
                except Exception:
                    p['display_name'] = ''
                norm_profiles.append(p)
        profiles = norm_profiles
        api_pool.disconnect()
        return render(request, 'packages/profiles/index.html', {'router': router, 'hotspotId': hotspot_id, 'profiles': profiles})
    except Exception as e:
        messages.error(request, f'Failed to load profiles: {str(e)}')
        return redirect('packagespots.index', router_id=router_id)

@login_required
def package_get_hotspot_user_profile(request, router_id, hotspot_id, profile_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        profiles = api.get_resource('/ip/hotspot/user/profile').get()
        try:
            profiles = list(profiles)
        except Exception:
            pass
        # Find the requested profile by .id, id, or name
        profile = next((p for p in profiles if str(p.get('.id') or p.get('id') or p.get('name')) == str(profile_id)), None)
        api_pool.disconnect()
        if not profile:
            messages.error(request, 'Profile not found.')
            return redirect('packageprofiles.index', router_id=router_id, hotspot_id=hotspot_id)
        # Normalize profile keys for template use and compute display name
        try:
            profile = _normalize_routeros_dict(profile if isinstance(profile, dict) else dict(profile))
            raw = profile.get('name', '') or ''
            if raw.startswith('profile_'):
                s = raw[len('profile_'):]
                idx = s.find('-se')
                profile['display_name'] = s[:idx].strip() if idx != -1 else s.strip()
            else:
                profile['display_name'] = raw
            # Add aliases for template consumption
            try:
                profile['bandwidth'] = profile.get('rate_limit')
            except Exception:
                profile['bandwidth'] = None
            try:
                profile['duration'] = profile.get('keepalive_timeout')
            except Exception:
                profile['duration'] = None
        except Exception:
            try:
                profile['display_name'] = profile.get('name', '')
            except Exception:
                profile['display_name'] = ''
        return render(request, 'packages/profiles/show.html', {'router': router, 'hotspotId': hotspot_id, 'profile': profile})
    except Exception as e:
        messages.error(request, f'Failed to load profile: {str(e)}')
        return redirect('packageprofiles.index', router_id=router_id, hotspot_id=hotspot_id)

@login_required
def package_create_hotspot_user_profile(request, router_id, hotspot_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    return render(request, 'packages/profiles/create.html', {'router': router, 'hotspotId': hotspot_id})

@login_required
def package_store_hotspot_user_profile(request, router_id, hotspot_id):
    import logging
    # Simple prints for basic debugging (user requested plain prints)
    trace_msg = f"[TRACE] package_store_hotspot_user_profile called: method={request.method} path={request.path} router_id={router_id} hotspot_id={hotspot_id}"
    print(trace_msg, flush=True)
    try:
        with open('/tmp/bim_profile_debug.log', 'a') as _f:
            _f.write(trace_msg + '\n')
    except Exception:
        pass
    logging.getLogger(__name__).debug('Entered package_store_hotspot_user_profile for router %s hotspot %s with method %s', router_id, hotspot_id, request.method)
    if request.method == 'POST':
        # user-visible short slug (e.g. "5HRS500shs") that will be embedded into the router profile name
        slug = request.POST.get('slug')
        no_of_users = request.POST.get('no_of_users')
        bandwidth = request.POST.get('bandwidth')
        duration = request.POST.get('duration')
        router = get_object_or_404(Router, id=router_id, user=request.user)
        import logging
        import sys
        logger = logging.getLogger(__name__)
        # Attach a temporary stdout handler so debug/info logs are visible in the terminal
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setLevel(logging.DEBUG)
        stdout_handler.setFormatter(logging.Formatter('[%(levelname)s] %(name)s: %(message)s'))
        logger.addHandler(stdout_handler)
        api_pool = None
        try:
            api_pool = initialize_client(router)
            api = api_pool.get_api()
            # Construct a RouterOS-friendly profile name exactly matching the required literal pattern.
            # User types a short slug (e.g. "5HRS500shs"). We prepend "profile_" and append the fixed suffix
            # used by downstream scripts.
            def build_profile_name(slug_value, no_users, bw, dur):
                base = ''
                if slug_value:
                    base = f'profile_{slug_value}'

                # Extract numeric cost from slug (first numeric sequence), if any
                import re
                cost = ''
                if slug_value:
                    matches = re.findall(r'(\d+(?:\.\d+)?)', slug_value)
                    if matches:
                        # Prefer a match with a decimal point, otherwise pick the longest numeric match
                        dec_matches = [m for m in matches if '.' in m]
                        if dec_matches:
                            cost = dec_matches[0]
                        else:
                            cost = max(matches, key=lambda s: len(s))
                    # Normalize to one decimal place (so '5000' becomes '5000.0') when numeric
                    try:
                        cost = f"{float(cost):.1f}"
                    except Exception:
                        # leave cost as-is if conversion fails
                        pass
                ut_token = dur if dur else '00:00:00'

                # Build literal suffix exactly as requested:
                # -se:BIM-co:<cost>-pr:-lu:7-lp:7-ut:<duration>-bt:-kt:false-nu:true-np:true-tp:2
                suffix = f'-se:BIM-co:{cost}-pr:-lu:7-lp:7-ut:{ut_token}-bt:-kt:false-nu:true-np:true-tp:2'

                return base + suffix

            # slug is mandatory - if missing, return error
            if not slug:
                raise ValueError('Profile slug is required')
            final_name = build_profile_name(slug, no_of_users, bandwidth, duration)

            # Debug: log POST payload and computed final_name
            logger.debug('POST data for profile create: slug=%r no_of_users=%r bandwidth=%r duration=%r', slug, no_of_users, bandwidth, duration)
            post_msg = f"[DEBUG] package_store_hotspot_user_profile POST slug={slug} no_of_users={no_of_users} bandwidth={bandwidth} duration={duration}"
            print(post_msg, flush=True)
            name_msg = f"[DEBUG] Computed final router profile name: {final_name}"
            print(name_msg, flush=True)
            try:
                with open('/tmp/bim_profile_debug.log', 'a') as _f:
                    _f.write(post_msg + '\n')
                    _f.write(name_msg + '\n')
            except Exception:
                pass

            profile_resource = api.get_resource('/ip/hotspot/user/profile')
            profile_resource = api.get_resource('/ip/hotspot/user/profile')
            # Use RouterOS hyphenated parameter names to ensure the API accepts them
            add_params = {
                'name': final_name,
                'shared-users': no_of_users,
                'rate-limit': bandwidth,
                'session-timeout': '00:00:00',
                'idle-timeout': '00:00:00',
                'mac-cookie-timeout': '30d',
                'keepalive-timeout': duration,
            }
            logger.debug('Calling profile_resource.add with params: %r', add_params)
            print(f"[DEBUG] profile_resource.add params: {add_params}", flush=True)
            # Send to router and capture the raw response (if any) for logging
            try:
                add_result = profile_resource.add(**add_params)
            except Exception as e_add:
                # Log and re-raise to be caught by outer except
                logger.exception('Router add() raised exception: %s', e_add)
                print('[ERROR] Exception from profile_resource.add:\n' + str(e_add))
                raise
            else:
                # log whatever the API returned (often a typed promise or dict)
                logger.debug('profile_resource.add returned: %r', add_result)
                try:
                    print(f"[DEBUG] profile_resource.add returned: {list(add_result) if add_result is not None else add_result}", flush=True)
                except Exception:
                    print(f"[DEBUG] profile_resource.add returned (repr): {repr(add_result)}", flush=True)
            # Read-after-write verification: try to fetch the profile back from router
            try:
                created = api.get_resource('/ip/hotspot/user/profile').get(name=final_name)
                created_list = list(created) if created is not None else []
            except Exception:
                created_list = []
            # Log what we saw when reading back
            logger.debug('Read-after-write created_list: %r', created_list)
            print(f"[DEBUG] Read-after-write created_list: {created_list}", flush=True)
            if created_list:
                logger.info('Profile created on router: %s', final_name)
            else:
                logger.warning('Profile not found after creation attempt: %s', final_name)
            messages.success(request, 'Profile created successfully.')
            # Redirect to index and highlight the newly created profile by name
            target = f"{reverse('packageprofiles.index', kwargs={'router_id': router_id, 'hotspot_id': hotspot_id})}?highlight={quote(final_name)}"
            # Final logging before redirecting
            logger.debug('About to redirect to: %s (created_on_router=%s)', target, bool(created_list))
            redirect_msg = f"[TRACE] package_store_hotspot_user_profile about to redirect to: {target} created_on_router={bool(created_list)}"
            print(redirect_msg, flush=True)
            try:
                with open('/tmp/bim_profile_debug.log', 'a') as _f:
                    _f.write(redirect_msg + '\n')
            except Exception:
                pass
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'message': 'Profile created', 'created_on_router': bool(created_list), 'router_name': final_name, 'redirect': target})
            return redirect(target)
        except Exception as e:
            # Capture full traceback and print to terminal so user can paste it
            import traceback
            tb = traceback.format_exc()
            logger.exception('Failed to create profile for router %s hotspot %s: %s', router_id, hotspot_id, e)
            err_msg = '[ERROR] Exception during profile create:\n' + tb
            print(err_msg, flush=True)
            try:
                with open('/tmp/bim_profile_debug.log', 'a') as _f:
                    _f.write(err_msg + '\n')
            except Exception:
                pass
            messages.error(request, f'Failed to create profile: {str(e)}')
            # If AJAX/JSON client, return the traceback and the params used
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'error': str(e), 'traceback': tb, 'params': {'slug': slug, 'no_of_users': no_of_users, 'bandwidth': bandwidth, 'duration': duration}}, status=500)
            return redirect('packagespots.create', router_id=router_id, hotspot_id=hotspot_id)
        finally:
            try:
                if api_pool is not None:
                    api_pool.disconnect()
            except Exception:
                logging.getLogger(__name__).exception('Failed to disconnect api_pool for profile create %s', router_id)
            # remove the temporary stdout handler if it exists (we relied on prints anyway)
            try:
                logger.removeHandler(stdout_handler)
            except Exception:
                pass
    return redirect('packagespots.create', router_id=router_id, hotspot_id=hotspot_id)
    # This print should never be reached because redirect returns, but kept for parity
    # (leftover safe_log call removed intentionally)

@login_required
def package_edit_hotspot_user_profile(request, router_id, hotspot_id, profile_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        profiles = api.get_resource('/ip/hotspot/user/profile').get()
        try:
            profiles = list(profiles)
        except Exception:
            pass
        # Try to match by .id, id, or name (string compare)
        profile = next((p for p in profiles if str(p.get('.id')) == str(profile_id) or str(p.get('id')) == str(profile_id) or str(p.get('name')) == str(profile_id)), None)
        if not profile:
            # Log available profile ids for debugging
            import logging
            logging.warning('Profile not found. Searched for: %r. Available: %r', profile_id, [p.get('.id') or p.get('id') or p.get('name') for p in profiles])
        api_pool.disconnect()
        if not profile:
            messages.error(request, 'Profile not found.')
            return redirect('packageprofiles.index', router_id=router_id, hotspot_id=hotspot_id)
        # compute display name for edit form
        try:
            raw = profile.get('name', '') or ''
            if raw.startswith('profile_'):
                s = raw[len('profile_'):]
                idx = s.find('-se')
                profile['display_name'] = s[:idx].strip() if idx != -1 else s.strip()
            else:
                profile['display_name'] = raw
        except Exception:
            profile['display_name'] = profile.get('name', '')

        # Normalize and add bandwidth/duration aliases so the edit form can prefill them
        try:
            if isinstance(profile, dict):
                profile = _normalize_routeros_dict(profile)
            else:
                profile = _normalize_routeros_dict(dict(profile))
        except Exception:
            try:
                profile = dict(profile) if not isinstance(profile, dict) else profile
            except Exception:
                pass
        try:
            profile['bandwidth'] = profile.get('rate_limit')
        except Exception:
            profile['bandwidth'] = None
        try:
            profile['duration'] = profile.get('keepalive_timeout')
        except Exception:
            profile['duration'] = None

        return render(request, 'packages/profiles/edit.html', {'router': router, 'hotspotId': hotspot_id, 'profile': profile})
    except Exception as e:
        messages.error(request, f'Failed to load profile: {str(e)}')
        return redirect('packageprofiles.index', router_id=router_id, hotspot_id=hotspot_id)

@login_required
def package_update_hotspot_user_profile(request, router_id, hotspot_id, profile_id):
    import logging
    logging.getLogger(__name__).debug('Entered package_update_hotspot_user_profile for router %s hotspot %s profile %s with method %s', router_id, hotspot_id, profile_id, request.method)
    if request.method == 'POST':
        # Simple prints to trace update flow
        upd_trace = f"[TRACE] package_update_hotspot_user_profile called: method={request.method} path={request.path} router_id={router_id} hotspot_id={hotspot_id} profile_id={profile_id}"
        print(upd_trace, flush=True)
        try:
            with open('/tmp/bim_profile_debug.log', 'a') as _f:
                _f.write(upd_trace + '\n')
        except Exception:
            pass
        print(f"[DEBUG] package_update POST slug={request.POST.get('slug')} no_of_users={request.POST.get('no_of_users')} bandwidth={request.POST.get('bandwidth')} duration={request.POST.get('duration')}", flush=True)
        # only slug is user-editable
        slug = request.POST.get('slug')
        no_of_users = request.POST.get('no_of_users')
        bandwidth = request.POST.get('bandwidth')
        duration = request.POST.get('duration')
        router = get_object_or_404(Router, id=router_id, user=request.user)
        import logging
        logger = logging.getLogger(__name__)
        api_pool = None
        try:
            api_pool = initialize_client(router)
            api = api_pool.get_api()
            def build_profile_name(slug_value, no_users, bw, dur):
                base = ''
                if slug_value:
                    base = f'profile_{slug_value}'

                import re
                cost = ''
                if slug_value:
                    matches = re.findall(r'(\d+(?:\.\d+)?)', slug_value)
                    if matches:
                        dec_matches = [m for m in matches if '.' in m]
                        if dec_matches:
                            cost = dec_matches[0]
                        else:
                            cost = max(matches, key=lambda s: len(s))
                    try:
                        cost = f"{float(cost):.1f}"
                    except Exception:
                        pass

                ut_token = dur if dur else '00:00:00'
                suffix = f'-se:BIM-co:{cost}-pr:-lu:7-lp:7-ut:{ut_token}-bt:-kt:false-nu:true-np:true-tp:2'

                return base + suffix

            if not slug:
                raise ValueError('Profile slug is required')
            final_name = build_profile_name(slug, no_of_users, bandwidth, duration)

            profile_resource = api.get_resource('/ip/hotspot/user/profile')
            import logging
            logger = logging.getLogger(__name__)
            try:
                logger.debug('Final profile name to set: %s', final_name)
                profile_resource.set(
                    id=profile_id,
                    **{
                        'name': final_name,
                        'shared-users': no_of_users,
                        'rate-limit': bandwidth,
                        'session-timeout': '00:00:00',
                        'idle-timeout': '00:00:00',
                        'mac-cookie-timeout': '30d',
                        'keepalive-timeout': duration,
                    }
                )
                # Read-after-write verification for update
                try:
                    verify = api.get_resource('/ip/hotspot/user/profile').get(name=final_name)
                    verify_list = list(verify) if verify is not None else []
                except Exception:
                    verify_list = []
                    print(f"[DEBUG] package_update_hotspot_user_profile: exception reading back profile {final_name}", flush=True)
                    try:
                        with open('/tmp/bim_profile_debug.log', 'a') as _f:
                            _f.write(f"[DEBUG] exception reading back profile {final_name}\n")
                    except Exception:
                        pass
                if verify_list:
                    logger.info('Profile updated on router: %s', final_name)
                else:
                    logger.warning('Profile update not observed on router: %s', final_name)
                print(f"[DEBUG] package_update_hotspot_user_profile verify_list: {verify_list}", flush=True)
                try:
                    with open('/tmp/bim_profile_debug.log', 'a') as _f:
                        _f.write(str(verify_list) + '\n')
                except Exception:
                    pass
                messages.success(request, 'Profile updated successfully.')
                target = f"{reverse('packageprofiles.index', kwargs={'router_id': router_id, 'hotspot_id': hotspot_id})}?highlight={quote(final_name)}"
                logging.getLogger(__name__).info('Profile %s updated for router %s; redirecting to %s', profile_id, router_id, target)
                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({'message': 'Profile updated', 'updated_on_router': bool(verify_list), 'router_name': final_name, 'redirect': target}, status=200)
                return redirect(target)
            except Exception as inner_e:
                logger.exception('Failed to set profile %s: %s', profile_id, inner_e)
                messages.error(request, f'Failed to update profile: {str(inner_e)}')
                # return JSON error for AJAX clients
                if request.headers.get('Accept') == 'application/json':
                    return JsonResponse({'error': str(inner_e)}, status=500)
                return redirect('packagespots.edit', router_id=router_id, hotspot_id=hotspot_id, profile_id=profile_id)
        except Exception as e:
            import logging
            logging.exception('Unexpected error while updating profile %s: %s', profile_id, e)
            messages.error(request, f'Failed to update profile: {str(e)}')
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'error': str(e)}, status=500)
            return redirect('packagespots.edit', router_id=router_id, hotspot_id=hotspot_id, profile_id=profile_id)
        finally:
            try:
                if api_pool is not None:
                    api_pool.disconnect()
            except Exception:
                logging.getLogger(__name__).exception('Failed to disconnect api_pool for profile update %s', profile_id)
    return redirect('packagespots.edit', router_id=router_id, hotspot_id=hotspot_id, profile_id=profile_id)

@login_required
def package_delete_hotspot_user_profile(request, router_id, hotspot_id, profile_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        profile_resource = api.get_resource('/ip/hotspot/user/profile')
        profile_resource.remove(id=profile_id)
        api_pool.disconnect()
        messages.success(request, 'Profile deleted successfully.')
    except Exception as e:
        messages.error(request, f'Failed to delete profile: {str(e)}')
    return redirect('packageprofiles.index', router_id=router_id, hotspot_id=hotspot_id)

@login_required
def package_disable_hotspot_user_profile(request, router_id, hotspot_id, profile_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        # Disable profile by setting 'disabled' to 'true' (if supported by RouterOS)
        api.get_resource('/ip/hotspot/user/profile').set(id=profile_id, disabled='true')
        api_pool.disconnect()
        messages.success(request, 'Profile disabled successfully.')
        return redirect('packageprofiles.index', router_id=router_id, hotspot_id=hotspot_id)
    except Exception as e:
        messages.error(request, f'Failed to disable profile: {str(e)}')
        return redirect('packageprofiles.index', router_id=router_id, hotspot_id=hotspot_id)

# ====================
# End Package Views Block
# ====================

# ====================
# Voucher Views Block
# Converted from Laravel VoucherController
# ====================

@login_required
def voucher_list_routers(request):
    routers = Router.objects.filter(user=request.user).order_by('-created_at')
    paginator = Paginator(routers, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    context = {
        'routers': page_obj,
        'page_obj': page_obj,
        'paginator': paginator
    }
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({'routers': list(page_obj.object_list.values()), 'message': 'Routers retrieved successfully', 'page': page_obj.number, 'num_pages': paginator.num_pages})
    return render(request, 'vouchers/index.html', context)

@login_required
def voucher_list_all_hotspot_servers(request, router_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        print(f"[DEBUG] vouchers: fetching hotspots for router {router_id}")
        hotspots = api.get_resource('/ip/hotspot').get()
        try:
            hotspots = list(hotspots)
        except Exception:
            # If the resource returned a single dict or unexpected type, coerce to list when possible
            try:
                # wrap single mapping in a list
                if isinstance(hotspots, dict):
                    hotspots = [hotspots]
                else:
                    hotspots = list(hotspots)
            except Exception:
                # fallback to empty list to avoid template errors
                hotspots = []
        # Normalize RouterOS dict keys and map .id -> id so templates can use hotspot.id and dot/underscore-safe keys
        norm_hotspots = []
        for h in hotspots:
            if isinstance(h, dict):
                nh = _normalize_routeros_dict(h)
                # map routeros .id to id for template usage
                if '.id' in h:
                    nh['id'] = str(h.get('.id'))
                elif 'id' in h:
                    nh['id'] = str(h.get('id'))
                norm_hotspots.append(nh)
            else:
                norm_hotspots.append(h)
        hotspots = norm_hotspots
        print(f"[DEBUG] vouchers: fetched {len(hotspots)} hotspots (router={router_id})")
        api_pool.disconnect()
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'router': str(router.id), 'hotspots': hotspots})
        return render(request, 'vouchers/hotspots.html', {'router': router, 'hotspots': hotspots})
    except Exception as e:
        error = f'Failed to fetch hotspots: {str(e)}'
        print(f"[ERROR] vouchers: failed to fetch hotspots for router {router_id}: {error}")
        logging.getLogger(__name__).exception('Failed to fetch hotspots for router %s', router_id)
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'error': error}, status=500)
        return redirect('vouchers.index')

@login_required
def voucher_list_hotspot_users(request, router_id, hotspot_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        users = api.get_resource('/ip/hotspot/user').get()
        try:
            users = list(users)
        except Exception:
            users = [users] if isinstance(users, dict) else []
        # normalize users so templates can access user.id and underscore keys
        norm_users = []
        for u in users:
            if isinstance(u, dict):
                nu = _normalize_routeros_dict(u)
                if '.id' in u:
                    nu['id'] = str(u.get('.id'))
                elif 'id' in u:
                    nu['id'] = str(u.get('id'))
                norm_users.append(nu)
            else:
                norm_users.append(u)
        users = norm_users
        profiles = api.get_resource('/ip/hotspot/user/profile').get()
        try:
            profiles = list(profiles)
        except Exception:
            pass
        hotspot_servers = api.get_resource('/ip/hotspot').get()
        try:
            hotspot_servers = list(hotspot_servers)
        except Exception:
            hotspot_servers = [hotspot_servers] if isinstance(hotspot_servers, dict) else []
        # normalize hotspot_servers as well
        norm_servers = []
        for s in hotspot_servers:
            if isinstance(s, dict):
                ns = _normalize_routeros_dict(s)
                if '.id' in s:
                    ns['id'] = str(s.get('.id'))
                elif 'id' in s:
                    ns['id'] = str(s.get('id'))
                norm_servers.append(ns)
            else:
                norm_servers.append(s)
        hotspot_servers = norm_servers
        api_pool.disconnect()
        print(f"[DEBUG] vouchers: voucher_list_hotspot_users called for router={router_id} hotspot_id={hotspot_id} -> total_users={len(users)} total_servers={len(hotspot_servers)}")
        # Try to resolve the selected hotspot's server name (RouterOS 'name') from hotspot_servers
        selected_server_name = None
        try:
            for s in hotspot_servers:
                if isinstance(s, dict):
                    if str(s.get('id')) == str(hotspot_id):
                        selected_server_name = s.get('name')
                        break
                    if s.get('name') == hotspot_id:
                        selected_server_name = s.get('name')
                        break
        except Exception:
            selected_server_name = None
        if selected_server_name:
            filtered_users = [u for u in users if isinstance(u, dict) and u.get('server') == selected_server_name]
            print(f"[DEBUG] vouchers: resolved hotspot name='{selected_server_name}', users for hotspot={len(filtered_users)}")
            users = filtered_users
        else:
            # If we couldn't resolve the server name, try a best-effort match on server field
            try:
                filtered_users = [u for u in users if isinstance(u, dict) and hotspot_id in (u.get('server') or '')]
                print(f"[DEBUG] vouchers: no server name resolved, best-effort matched users={len(filtered_users)}")
                users = filtered_users
            except Exception:
                pass
        # record counts for terminal debugging (keep page output clean)
        try:
            raw_users_count = len(norm_users)
        except Exception:
            raw_users_count = len(users) if hasattr(users, '__len__') else 0

        paginator = Paginator(users, 20)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        from django.conf import settings
        # determine display name for selected hotspot (fall back to hotspot_id)
        display_hotspot_name = None
        try:
            # hotspot_servers entries are dicts with 'id' and 'name'
            for s in hotspot_servers:
                if isinstance(s, dict) and str(s.get('id')) == str(hotspot_id):
                    display_hotspot_name = s.get('name')
                    break
        except Exception:
            display_hotspot_name = None

        context = {
            'router': router,
            'hotspotId': hotspot_id,
            'hotspot_name': display_hotspot_name or hotspot_id,
            'users': page_obj,
            'profiles': profiles,
            'hotspotServers': hotspot_servers,
            # do not expose debug data to users in the page; use terminal prints instead
        }
        # Print simplified diagnostics to terminal (developer-facing)
        try:
            print(f"[DEBUG] vouchers: hotspot_users router={router_id} hotspot={hotspot_id} raw_users={raw_users_count} filtered_users={len(users)} servers={len(hotspot_servers)}")
            # show up to 5 names for quick terminal inspection
            names = [u.get('name') for u in users[:5] if isinstance(u, dict)]
            print(f"[DEBUG] vouchers: sample_user_names={names}")
        except Exception:
            pass
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({
                'users': list(page_obj.object_list),
                'profiles': profiles,
                'hotspotServers': hotspot_servers,
                'page': page_obj.number,
                'num_pages': paginator.num_pages
            })
        return render(request, 'vouchers/users.html', context)
    except Exception as e:
        error = f'Failed to load users: {str(e)}'
        print(f"[ERROR] vouchers: failed to load users for router {router_id} hotspot {hotspot_id}: {error}")
        logging.getLogger(__name__).exception('Failed to load users for router %s hotspot %s', router_id, hotspot_id)
        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({'error': error}, status=500)
        return redirect('voucherspots.index', router_id=router_id)

@login_required
def voucher_create_hotspot_user(request, router_id, hotspot_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        hotspot_servers = api.get_resource('/ip/hotspot').get()
        try:
            hotspot_servers = list(hotspot_servers)
        except Exception:
            pass
        profiles = api.get_resource('/ip/hotspot/user/profile').get()
        try:
            profiles = list(profiles)
        except Exception:
            pass
        # Normalize profiles for template consumption (provide display_name, slug, router_name)
        norm_profiles = []
        try:
            for p in profiles:
                p_dict = p if isinstance(p, dict) else dict(p)
                p_norm = _normalize_routeros_dict(p_dict)
                raw = p_norm.get('name', '') or ''
                p_norm['router_name'] = raw
                # compute display-friendly slug (strip leading 'profile_' and trailing suffix)
                if raw.startswith('profile_'):
                    s = raw[len('profile_'):]
                    idx = s.find('-se')
                    display = s[:idx].strip() if idx != -1 else s.strip()
                else:
                    display = raw
                p_norm['display_name'] = display
                # provide a short slug for comparison (the part before suffix)
                p_norm['slug'] = display
                # alias common keys for template use
                p_norm['bandwidth'] = p_norm.get('rate_limit')
                p_norm['duration'] = p_norm.get('keepalive_timeout')
                norm_profiles.append(p_norm)
        except Exception:
            # fallback: pass original list through
            norm_profiles = profiles
        api_pool.disconnect()
        context = {
            'router': router,
            'hotspotId': hotspot_id,
            'hotspotServers': hotspot_servers,
            'profiles': norm_profiles
        }
        return render(request, 'vouchers/users/create.html', context)
    except Exception as e:
        error = f'Failed to load data: {str(e)}'
        return redirect('voucherspots.index', router_id=router_id)

@login_required
def voucher_store_hotspot_user(request, router_id, hotspot_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    if request.method == 'POST':
        username = request.POST.get('username')
        profile = request.POST.get('profile')
        hotspot_server = request.POST.get('hotspot_server')
        password = request.POST.get('password')
        try:
            api_pool = initialize_client(router)
            api = api_pool.get_api()
            # allow 'profile' to be either the full router-side name or the user-facing slug
            resolved = resolve_router_profile_name(api, profile)
            if resolved:
                profile_name_for_router = resolved
            else:
                profile_name_for_router = profile
            profile_data = api.get_resource('/ip/hotspot/user/profile').get(name=profile_name_for_router)
            try:
                profile_data = list(profile_data)
            except Exception:
                pass
            keepalive_timeout = profile_data[0]['keepalive-timeout'] if profile_data and 'keepalive-timeout' in profile_data[0] else None
            add_args = {
                'name': username,
                'profile': profile,
                'server': hotspot_server,
                'comment': f"Microtiket-dc:created"
            }
            if keepalive_timeout:
                add_args['limit-uptime'] = keepalive_timeout
            if password:
                add_args['password'] = password
            api.get_resource('/ip/hotspot/user').add(**add_args)
            api_pool.disconnect()
            # Save to VoucherUser model
            VoucherUser.objects.create(router=router, username=username)
            messages.success(request, 'Voucher created successfully.')
            return redirect('voucherspots.users', router_id=router_id, hotspot_id=hotspot_id)
        except Exception as e:
            error = f'Failed to create voucher: {str(e)}'
            messages.error(request, error)
            return redirect('voucherspots.users.create', router_id=router_id, hotspot_id=hotspot_id)
    return redirect('voucherspots.users.create', router_id=router_id, hotspot_id=hotspot_id)

@login_required
def voucher_edit_hotspot_user(request, router_id, hotspot_id, user_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        user_data = api.get_resource('/ip/hotspot/user').get(**{'.id': user_id})
        try:
            user_data = list(user_data)
        except Exception:
            pass
        user = user_data[0] if user_data else None
        profiles = api.get_resource('/ip/hotspot/user/profile').get()
        try:
            profiles = list(profiles)
        except Exception:
            pass
        # Normalize profiles for template consumption (provide display_name, slug, router_name)
        norm_profiles = []
        try:
            for p in profiles:
                p_dict = p if isinstance(p, dict) else dict(p)
                p_norm = _normalize_routeros_dict(p_dict)
                raw = p_norm.get('name', '') or ''
                p_norm['router_name'] = raw
                if raw.startswith('profile_'):
                    s = raw[len('profile_'):]
                    idx = s.find('-se')
                    display = s[:idx].strip() if idx != -1 else s.strip()
                else:
                    display = raw
                p_norm['display_name'] = display
                p_norm['slug'] = display
                p_norm['bandwidth'] = p_norm.get('rate_limit')
                p_norm['duration'] = p_norm.get('keepalive_timeout')
                norm_profiles.append(p_norm)
        except Exception:
            norm_profiles = profiles
        api_pool.disconnect()
        if not user:
            messages.error(request, 'User not found.')
            return redirect('voucherspots.users', router_id=router_id, hotspot_id=hotspot_id)
        context = {
            'router': router,
            'hotspotId': hotspot_id,
            'user': user,
            'profiles': norm_profiles
        }
        return render(request, 'vouchers/users/edit.html', context)
    except Exception as e:
        error = f'Failed to fetch voucher: {str(e)}'
        messages.error(request, error)
        return redirect('voucherspots.users', router_id=router_id, hotspot_id=hotspot_id)

@login_required
def voucher_update_hotspot_user(request, router_id, hotspot_id, user_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    if request.method == 'POST':
        name = request.POST.get('name')
        password = request.POST.get('password')
        profile = request.POST.get('profile')
        try:
            api_pool = initialize_client(router)
            api = api_pool.get_api()
            resolved = resolve_router_profile_name(api, profile)
            profile_name_for_router = resolved if resolved else profile
            profile_data = api.get_resource('/ip/hotspot/user/profile').get(name=profile_name_for_router)
            try:
                profile_data = list(profile_data)
            except Exception:
                pass
            keepalive_timeout = profile_data[0]['keepalive-timeout'] if profile_data and 'keepalive-timeout' in profile_data[0] else None
            update_args = {
                '.id': user_id,
                'name': name,
                'profile': profile_name_for_router
            }
            if keepalive_timeout:
                update_args['limit-uptime'] = keepalive_timeout
            if password:
                update_args['password'] = password
            api.get_resource('/ip/hotspot/user').set(**update_args)
            api_pool.disconnect()
            messages.success(request, 'Voucher updated successfully.')
            return redirect('voucherspots.users', router_id=router_id, hotspot_id=hotspot_id)
        except Exception as e:
            error = f'Failed to update voucher: {str(e)}'
            messages.error(request, error)
            return redirect('voucherspots.users.edit', router_id=router_id, hotspot_id=hotspot_id, user_id=user_id)
    return redirect('voucherspots.users.edit', router_id=router_id, hotspot_id=hotspot_id, user_id=user_id)

@login_required
def voucher_disable_hotspot_user(request, router_id, hotspot_id, user_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        api.get_resource('/ip/hotspot/user').set(**{'.id': user_id, 'disabled': 'true'})
        api_pool.disconnect()
        messages.success(request, 'Voucher disabled successfully.')
        return redirect('voucherspots.users', router_id=router_id, hotspot_id=hotspot_id)
    except Exception as e:
        error = f'Failed to disable voucher: {str(e)}'
        messages.error(request, error)
        return redirect('voucherspots.users', router_id=router_id, hotspot_id=hotspot_id)

@login_required
def voucher_delete_hotspot_user(request, router_id, hotspot_id, user_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    try:
        api_pool = initialize_client(router)
        api = api_pool.get_api()
        api.get_resource('/ip/hotspot/user').remove(**{'.id': user_id})
        api_pool.disconnect()
        messages.success(request, 'Voucher deleted successfully.')
        return redirect('voucherspots.users', router_id=router_id, hotspot_id=hotspot_id)
    except Exception as e:
        error = f'Failed to delete voucher: {str(e)}'
        messages.error(request, error)
        return redirect('voucherspots.users', router_id=router_id, hotspot_id=hotspot_id)

def voucher_parse_time_to_seconds(time_str):
    parts = {'h': 3600, 'm': 60, 's': 1}
    seconds = 0
    matches = re.findall(r'(\d+)([hms])', time_str)
    for value, unit in matches:
        seconds += int(value) * parts[unit]
    return seconds

def voucher_convert_keepalive_timeout_to_hours(keepalive_timeout):
    match = re.match(r'^(\d+)([dhmsw])$', keepalive_timeout)
    if match:
        value, unit = int(match.group(1)), match.group(2)
        if unit == 'w':
            return f"{(value * 7) * 24}h"
        elif unit == 'd':
            return f"{value * 24}h"
        elif unit == 'h':
            return f"{value}h"
        elif unit == 'm':
            return f"{round(value / 60, 2)}h"
        elif unit == 's':
            return f"{round(value / 3600, 2)}h"
        else:
            raise RuntimeError(f'Unsupported time unit: {unit}')
    else:
        raise RuntimeError(f'Invalid keepalive-timeout format: {keepalive_timeout}')

def voucher_generate_user_on_router(router, profile, hotspot_id):
    api_pool = initialize_client(router)
    api = api_pool.get_api()
    username = f"user_{str(datetime.datetime.now().timestamp()).replace('.', '')[-7:]}"
    # accept slug or full router profile name
    resolved = resolve_router_profile_name(api, profile)
    if resolved:
        profile_name_for_router = resolved
    else:
        profile_name_for_router = profile
    profile_data = api.get_resource('/ip/hotspot/user/profile').get(name=profile_name_for_router)
    try:
        profile_data = list(profile_data)
    except Exception:
        pass
    if not profile_data:
        raise RuntimeError(f'Profile not found: {profile}')
    keepalive_timeout = profile_data[0].get('keepalive-timeout')
    if not keepalive_timeout:
        raise RuntimeError(f'Keepalive-timeout not found in profile: {profile}')
    limit_uptime = voucher_convert_keepalive_timeout_to_hours(keepalive_timeout)
    timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
    comment = f"Microtiket-dc:{timestamp}-ot:4"
    api.get_resource('/ip/hotspot/user').add(
        name=username,
        profile=profile_name_for_router,
        server=hotspot_id,
        limit_uptime=limit_uptime,
        comment=comment
    )
    api_pool.disconnect()
    VoucherUser.objects.create(router=router, username=username)
    return username

def voucher_generate_hotspot_users(router, profile_name, hotspot_id, number_of_users):
    api_pool = initialize_client(router)
    api = api_pool.get_api()
    # accept either slug or router-side name
    resolved = resolve_router_profile_name(api, profile_name)
    profile_name_for_router = resolved if resolved else profile_name
    profile_data = api.get_resource('/ip/hotspot/user/profile').get(name=profile_name_for_router)
    try:
        profile_data = list(profile_data)
    except Exception:
        pass
    if not profile_data:
        raise RuntimeError('Profile not found.')
    keepalive_timeout = profile_data[0].get('keepalive-timeout')
    if not keepalive_timeout:
        raise RuntimeError('Keepalive timeout not found in the profile.')
    users = []
    for i in range(number_of_users):
        username = f"user_{str(datetime.datetime.now().timestamp()).replace('.', '')[-7:]}_{i}"
        timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
        comment = f"Mikroticket-dc:{timestamp}-ot:4"
        api.get_resource('/ip/hotspot/user').add(
            name=username,
            profile=profile_name_for_router,
            server=hotspot_id,
            limit_uptime=keepalive_timeout,
            comment=comment
        )
        VoucherUser.objects.create(router=router, username=username)
    # QR needs the router-side profile name for login; use resolved router name
    qr_url = f"/hotspot/login?user={username}&profile={profile_name_for_router}"
    qr = qrcode.make(qr_url)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_code = ContentFile(buffer.getvalue())
    users.append({
        'username': username,
        # return the user-facing slug for UI display, but the router name is recorded elsewhere
        'profile': profile_name,
        'hotspot_server': hotspot_id,
        'router_name': router.name,
        'qr_code': qr_code,
    })
    api_pool.disconnect()
    return users

# Error handling utility for voucher views

def voucher_error_response(request, error, redirect_url=None, status=500):
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({'error': str(error)}, status=status)
    if redirect_url:
        messages.error(request, str(error))
        return redirect(redirect_url)
    return render(request, 'vouchers/index.html', {'error': str(error)})

@login_required
@require_POST
def voucher_generate_single_user_automatically(request):
    logging.info('Generating the single user automatically...')
    router_id = request.POST.get('router_id')
    hotspot_id = request.POST.get('hotspot_server')
    profile_name = request.POST.get('profile')

    try:
        router = get_object_or_404(Router, id=router_id, user=request.user)
        api_pool = initialize_client(router)
        api = api_pool.get_api()

        hotspots = api.get_resource('/ip/hotspot').get()
        try:
            hotspots = list(hotspots)
        except Exception:
            pass
        hotspot_exists = next((h for h in hotspots if h.get('name') == hotspot_id), None)
        if not hotspot_exists:
            raise RuntimeError('The specified hotspot does not exist on this router.')

        # resolve slug or router-side name to router-side profile name
        resolved = resolve_router_profile_name(api, profile_name)
        profile_name_for_router = resolved if resolved else profile_name
        profiles = api.get_resource('/ip/hotspot/user/profile').get()
        try:
            profiles = list(profiles)
        except Exception:
            pass
        profile = next((p for p in profiles if p.get('name') == profile_name_for_router), None)
        if not profile:
            raise Exception("Profile not found.")

        keepalive_timeout = profile.get('keepalive-timeout')
        if not keepalive_timeout:
            raise Exception("Keepalive timeout not found in the profile.")

        username = str(random.randint(1000000, 9999999))
        timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
        comment = f"Mikroticket-dc:{timestamp}-ot:4"

        api.get_resource('/ip/hotspot/user').add(
            name=username,
            profile=profile_name_for_router,
            server=hotspot_id,
            comment=comment
        )
        api_pool.disconnect()

        VoucherUser.objects.create(router=router, username=username)

        logging.info('MikroTik user created automatically', {
            'username': username,
            'profile': profile_name_for_router,
            'router': router_id,
            'server': hotspot_id,
            'comment': comment,
            'timestamp': timestamp
        })

        return JsonResponse({
            'success': True,
            'message': 'User generated successfully.',
            'username': username,
        })
    except RuntimeError as e:
        return JsonResponse({
            'success': False,
            'message': str(e),
        }, status=500)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'An unexpected error occurred: {str(e)}',
        }, status=500)
# ====================
# End Voucher Views Block
# ====================

# ====================
# Dashboard Views Block
# Converted from Laravel DashboardController
# ====================

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

    chart_data = list(
        Transaction.objects.filter(router__user=user)
        .annotate(date=TruncDate('created_at'))
        .values('date')
        .annotate(total=Sum('amount'))
        .order_by('-date')[:7]
    )

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

# ====================
# End Dashboard Views Block
# ====================

# ====================
# Notification Views Block
# Converted from Laravel NotificationController
# ====================

class NotificationService:
    def get_latest_notifications(self, user_id, router_ids, limit=15):
        # Placeholder: Replace with actual notification query logic
        # Example: Query a Notification model or join with VoucherUser/Transaction
        # Return a list of dicts with keys: timestamp, router, username, profile, server
        # For now, return empty list
        return []

@login_required
def notification_index(request):
    user = request.user
    router_ids = list(user.routers.values_list('id', flat=True))
    service = NotificationService()
    notifications = service.get_latest_notifications(user.id, router_ids, 1000)  # Get all, paginate below
    paginator = Paginator(notifications, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    context = {
        'notifications': page_obj,
        'notificationCount': paginator.count
    }
    return render(request, 'notifications/index.html', context)

@login_required
def notification_count(request):
    user = request.user
    router_ids = list(user.routers.values_list('id', flat=True))
    service = NotificationService()
    notifications = service.get_latest_notifications(user.id, router_ids, 5)
    return JsonResponse({
        'count': len(notifications),
        'notifications': notifications
    })

# ====================
# End Notification Views Block
# ====================

# ====================
# Transaction Views Block
# Converted from Laravel TransactionController
# ====================

@login_required
def transactions_index(request):
    user = request.user
    transactions = Transaction.objects.select_related('router').filter(router__user=user)

    # Filters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    status = request.GET.get('status')
    type_ = request.GET.get('type')

    if start_date and end_date:
        transactions = transactions.filter(created_at__date__range=[start_date, end_date])
    if status:
        transactions = transactions.filter(status=status)
    if type_:
        transactions = transactions.filter(type=type_)

    total_amount = transactions.aggregate(total_amount=Sum('amount'))['total_amount'] or 0
    paginator = Paginator(transactions.order_by('-created_at'), 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'transactions': page_obj,
        'total_amount': total_amount
    }
    return render(request, 'transactions/index.html', context)

@login_required
def transactions_export_excel(request):
    user = request.user
    transactions = Transaction.objects.select_related('router').filter(router__user=user)

    # Filters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    status = request.GET.get('status')
    type_ = request.GET.get('type')

    if start_date and end_date:
        transactions = transactions.filter(created_at__date__range=[start_date, end_date])
    if status:
        transactions = transactions.filter(status=status)
    if type_:
        transactions = transactions.filter(type=type_)

    df = pd.DataFrame(list(transactions.values('amount', 'type', 'reason', 'status', 'router__name', 'created_at')))
    df.rename(columns={'router__name': 'router_name'}, inplace=True)
    # Prefer Excel when openpyxl is available, otherwise fallback to CSV
    try:
        import openpyxl  # noqa: F401
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename=transactions.xlsx'
        df.to_excel(response, index=False)
        return response
    except Exception:
        # Fallback CSV
        import csv
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=transactions.csv'
        writer = csv.writer(response)
        writer.writerow(df.columns.tolist())
        for row in df.itertuples(index=False, name=None):
            writer.writerow([str(x) if x is not None else '' for x in row])
        return response

@login_required
def transactions_export_pdf(request):
    user = request.user
    transactions = Transaction.objects.select_related('router').filter(router__user=user)

    # Filters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    status = request.GET.get('status')
    type_ = request.GET.get('type')

    if start_date and end_date:
        transactions = transactions.filter(created_at__date__range=[start_date, end_date])
    if status:
        transactions = transactions.filter(status=status)
    if type_:
        transactions = transactions.filter(type=type_)

    html = render_to_string('transactions/pdf.html', {'transactions': transactions})
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename=transactions.pdf'
    pisa_status = pisa.CreatePDF(html, dest=response)
    if pisa_status.err:
        return HttpResponse('We had some errors with PDF generation')
    return response
    
# ====================
# End Transaction Views Block
# ====================

# ====================
# Withdraw Views Block
# Converted from Laravel WithdrawController
# ====================

def format_phone_number(phone, country_code='256'):
    cleaned = re.sub(r'\D', '', phone)
    if cleaned.startswith(country_code):
        return cleaned
    if cleaned.startswith('0'):
        return country_code + cleaned[1:]
    return cleaned

def calculate_withdraw_charge(amount):
    if amount <= 10000:
        return -abs(amount * 0.15)
    elif amount <= 50000:
        return -abs(amount * 0.10)
    else:
        return -abs(amount * 0.05)

@login_required
def withdraw_index(request):
    routers = Router.objects.filter(user=request.user)
    return render(request, 'withdraws/index.html', {'routers': routers})

@login_required
def withdraw_create(request, router_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    return render(request, 'withdraws/create.html', {'router': router})

@login_required
def withdraw_store(request, router_id):
    router = get_object_or_404(Router, id=router_id, user=request.user)
    if request.method != 'POST':
        return redirect('withdraw.create', router_id=router_id)

    amount = float(request.POST.get('amount', 0))
    phone = request.POST.get('phone', '')
    email = request.POST.get('email', '')
    hotspot_name = request.POST.get('hotspot_name', '')

    charge = calculate_withdraw_charge(abs(amount))
    balance = router.balance

    if balance - (abs(amount) + abs(charge)) < 0:
        messages.error(request, 'Insufficient funds to cover withdrawal and charges')
        return redirect('withdraw.create', router_id=router_id)

    try:
        with db_transaction.atomic():
            withdraw_tx = Transaction.objects.create(
                router=router,
                type='debit',
                amount=-abs(amount),
                reason='Owner Withdrawal',
                status='pending'
            )
            Transaction.objects.create(
                router=router,
                type='debit',
                amount=charge,
                reason='Withdrawal Charge',
                status='successful'
            )
            router.balance -= (abs(amount) + abs(charge))
            router.save()

            payout_id = f"simulated-{withdraw_tx.id}"
            transaction_status = 'pending'

            withdraw_tx.status = transaction_status
            withdraw_tx.metadata = {
                'payout_id': payout_id,
                'executed_at': str(timezone.now())
            }
            withdraw_tx.save()

            messages.success(request, 'Withdrawal initiated successfully. Processing may take up to 6 hours.')
            return redirect('withdraw.index')
    except Exception as e:
        messages.error(request, f'Withdrawal failed: {str(e)}')
        return redirect('withdraw.create', router_id=router_id)

# ====================
# End Withdraw Views Block
# ====================
