import uuid
import logging
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from .models import MoMoTransaction as Transaction
from .services import MoMoSandboxClient

logger = logging.getLogger(__name__)

@require_POST
def initiate_payment(request):
    # Expecting JSON or form data: amount, phone, currency, email (optional)
    data = request.POST if request.POST else request.json if hasattr(request, 'json') else None
    if not data:
        try:
            import json
            data = json.loads(request.body.decode() or '{}')
        except Exception:
            return HttpResponseBadRequest('Invalid payload')

    amount = data.get('amount')
    phone = data.get('phone')
    currency = data.get('currency', 'EUR')
    email = data.get('email')

    if not amount or not phone:
        return HttpResponseBadRequest('amount and phone are required')

    reference = str(uuid.uuid4())
    tx = Transaction.objects.create(reference=reference, amount=amount, currency=currency, phone=phone, email=email)

    client = MoMoSandboxClient()
    # create api user / apikey / token and issue request-to-pay
    if not client.create_api_user(reference):
        tx.status = 'api_user_failed'
        tx.save()
        return JsonResponse({'error': 'failed to create api user'}, status=500)

    api_key = client.create_api_key(reference)
    if not api_key:
        tx.status = 'api_key_failed'
        tx.save()
        return JsonResponse({'error': 'failed to create api key'}, status=500)

    access_token = client.create_access_token(reference, api_key)
    if not access_token:
        tx.status = 'access_token_failed'
        tx.save()
        return JsonResponse({'error': 'failed to create access token'}, status=500)

    transaction_id = client.request_to_pay(access_token, amount, currency, phone, reference)
    if not transaction_id:
        tx.status = 'request_failed'
        tx.save()
        return JsonResponse({'error': 'failed to request payment'}, status=500)

    tx.external_id = transaction_id
    tx.status = 'pending'
    tx.save()

    return JsonResponse({'message': 'Payment requested', 'reference': reference, 'transaction_id': transaction_id}, status=202)


from django.views.decorators.http import require_GET

@require_GET
def transaction_status(request, reference):
    try:
        tx = Transaction.objects.get(reference=reference)
    except Transaction.DoesNotExist:
        return JsonResponse({'error': 'not found'}, status=404)
    return JsonResponse({'reference': tx.reference, 'status': tx.status, 'external_id': tx.external_id})


@csrf_exempt
@require_POST
def momo_callback(request):
    # MoMo callback will POST JSON payload describing transaction result
    try:
        import json
        payload = json.loads(request.body.decode() or '{}')
    except Exception:
        payload = {}

    logger.info('MoMo callback received: %s', payload)

    # Extract the reference if present; MTN sends resourceUrl or headers with X-Reference-Id
    headers = {k.lower(): v for k, v in request.headers.items()}
    ref = headers.get('x-reference-id') or payload.get('referenceId') or payload.get('reference')

    if not ref:
        logger.warning('Callback without reference: %s', payload)
        return JsonResponse({'ok': False, 'reason': 'no reference'}, status=400)

    # Try to find the transaction by reference
    try:
        tx = Transaction.objects.get(reference=ref)
    except Transaction.DoesNotExist:
        # Maybe the external id is used
        tx = Transaction.objects.filter(external_id=ref).first()
        if not tx:
            logger.warning('Callback for unknown reference %s', ref)
            return JsonResponse({'ok': False, 'reason': 'unknown reference'}, status=404)

    # Simple mapping: payload may include status or transactionStatus
    status = payload.get('status') or payload.get('transactionStatus') or 'completed'
    tx.status = status
    tx.save()

    return JsonResponse({'ok': True})
