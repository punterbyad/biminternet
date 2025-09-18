from django.core.cache import cache
from django.utils import timezone
import datetime, time, secrets, hashlib

# Rate limiting constants
THROTTLE_LIMIT = 3  # Max attempts
THROTTLE_WINDOW = 3600  # 1 hour window for blocking after too many attempts
MIN_RESEND_DELAY = 300  # 5 minutes between OTP requests

def throttle_key(prefix, identifier):
    return f"throttle:{prefix}:{identifier}"

def otp_key(identifier):
    return f"otp:{identifier}"

def increment_throttle(prefix, identifier):
    key = throttle_key(prefix, identifier)
    data = cache.get(key)
    now = timezone.now()
    
    if not data:
        expiry = now + datetime.timedelta(seconds=THROTTLE_WINDOW)
        cache.set(key, {'count': 1, 'expiry': expiry.timestamp()}, THROTTLE_WINDOW)
        return {'count': 1, 'expiry': expiry.timestamp()}
    else:
        data['count'] = data.get('count', 0) + 1
        ttl = int(data['expiry'] - now.timestamp())
        if ttl < 0:
            expiry = now + datetime.timedelta(seconds=THROTTLE_WINDOW)
            cache.set(key, {'count': 1, 'expiry': expiry.timestamp()}, THROTTLE_WINDOW)
            return {'count': 1, 'expiry': expiry.timestamp()}
        cache.set(key, data, ttl)
        return data

def get_throttle(prefix, identifier):
    key = throttle_key(prefix, identifier)
    data = cache.get(key)
    return data or {'count': 0, 'expiry': 0}

def allowed_to_send(prefix, identifier):
    data = get_throttle(prefix, identifier)
    
    # Check if user has exceeded the limit
    if data['count'] >= THROTTLE_LIMIT:
        return False, "Too many attempts. Please try again in an hour."
    
    # Check if user is trying to resend too quickly
    last_otp_time = cache.get(f"last_otp_time:{identifier}")
    if last_otp_time:
        time_since_last = time.time() - last_otp_time
        if time_since_last < MIN_RESEND_DELAY:
            remaining = int(MIN_RESEND_DELAY - time_since_last)
            return False, f"Please wait {remaining} seconds before requesting another OTP."
    
    return True, ""

def seconds_until_available(prefix, identifier):
    data = get_throttle(prefix, identifier)
    now_ts = int(time.time())
    
    # If user is blocked due to too many attempts
    if data['count'] >= THROTTLE_LIMIT:
        if data.get('expiry', 0) <= now_ts:
            return 0
        return int(data.get('expiry', 0) - now_ts)
    
    # If user needs to wait before resending
    last_otp_time = cache.get(f"last_otp_time:{identifier}")
    if last_otp_time:
        time_since_last = time.time() - last_otp_time
        if time_since_last < MIN_RESEND_DELAY:
            return int(MIN_RESEND_DELAY - time_since_last)
    
    return 0

def make_otp():
    return f"{secrets.randbelow(10**6):06d}"

def store_otp(identifier, code, ttl=600):
    key = otp_key(identifier)
    cache.set(key, hashlib.sha256(code.encode()).hexdigest(), ttl)
    # Record the time this OTP was sent
    cache.set(f"last_otp_time:{identifier}", time.time(), ttl)

def verify_otp(identifier, code):
    key = otp_key(identifier)
    stored = cache.get(key)
    if not stored: 
        return False
    return stored == hashlib.sha256(code.encode()).hexdigest()

def fetch_killbill_context(user):
    """
    Killbill integration removed: return an empty, safe context so callers
    that expect kb_tenant/kb_accounts/kb_invoices continue to work.
    """
    return {
        "tenant": None,
        "accounts": [],
        "invoices": [],
    }

