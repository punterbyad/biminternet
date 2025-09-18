from django.conf import settings
from django.http import JsonResponse


class RequireMobileHeaderForJsonMiddleware:
    """If REQUIRE_MOBILE_HEADER_FOR_JSON is True, require requests with
    Content-Type: application/json to include X-Mobile-Client: 1 header.
    Returns 400 JSON error if missing.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            enabled = getattr(settings, 'REQUIRE_MOBILE_HEADER_FOR_JSON', False)
            if enabled:
                content_type = (request.META.get('CONTENT_TYPE') or request.headers.get('Content-Type') or '')
                if 'application/json' in content_type.lower():
                    # Allow configuring path prefixes that are exempt from this check
                    exempt_prefixes = getattr(settings, 'REQUIRE_MOBILE_HEADER_JSON_EXEMPT_PREFIXES', ['/routers/'])
                    path = request.path or ''
                    if any(path.startswith(p) for p in exempt_prefixes):
                        # This path is an internal router-management endpoint; skip header enforcement
                        return self.get_response(request)
                    if request.headers.get('X-Mobile-Client') != '1':
                        return JsonResponse({'error': 'X-Mobile-Client header required for JSON requests'}, status=400)
        except Exception:
            # Don't block request on middleware error; log at app-level if needed
            pass
        return self.get_response(request)
