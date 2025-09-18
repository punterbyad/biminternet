import uuid
import base64
import logging
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

class MoMoSandboxClient:
    """Minimal client for MTN MoMo Collection sandbox flows used in the tutorial.

    Methods implemented:
    - create_api_user(reference_id)
    - create_api_key(reference_id)
    - create_access_token(reference_id, api_key)
    - request_to_pay(access_token, amount, currency, phone, reference_id)

    This intentionally mirrors the Laravel example and the sandbox tutorial.
    """

    def __init__(self, target_environment='sandbox'):
        self.target_environment = target_environment
        self.api_base = 'https://sandbox.momodeveloper.mtn.com'
        self.subscription_key = getattr(settings, 'MOMO_SUBSCRIPTION_KEY', None)
        self.callback_url = getattr(settings, 'MOMO_CALLBACK_URL', None)
        if not self.subscription_key:
            logger.warning('MOMO_SUBSCRIPTION_KEY is not configured')

    def create_api_user(self, reference_id: str) -> bool:
        url = f"{self.api_base}/v1_0/apiuser"
        payload = {'providerCallbackHost': self.callback_url}
        headers = {
            'X-Reference-Id': str(reference_id),
            'Ocp-Apim-Subscription-Key': self.subscription_key,
            'Content-Type': 'application/json',
        }
        r = requests.post(url, json=payload, headers=headers)
        logger.debug('create_api_user %s -> %s', url, r.status_code)
        return r.status_code == 201

    def create_api_key(self, reference_id: str) -> str | None:
        url = f"{self.api_base}/v1_0/apiuser/{reference_id}/apikey"
        headers = {'Ocp-Apim-Subscription-Key': self.subscription_key, 'Content-Type': 'application/json'}
        r = requests.post(url, headers=headers)
        if r.ok:
            return r.json().get('apiKey')
        logger.error('create_api_key failed: %s', r.text)
        return None

    def create_access_token(self, reference_id: str, api_key: str) -> str | None:
        url = f"{self.api_base}/collection/token/"
        auth = base64.b64encode(f"{reference_id}:{api_key}".encode()).decode()
        headers = {'Authorization': f'Basic {auth}', 'Ocp-Apim-Subscription-Key': self.subscription_key}
        r = requests.post(url, headers=headers)
        if r.ok:
            return r.json().get('access_token')
        logger.error('create_access_token failed: %s', r.text)
        return None

    def request_to_pay(self, access_token: str, amount: str, currency: str, phone: str, reference_id: str) -> str | None:
        url = f"{self.api_base}/collection/v1_0/requesttopay"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'X-Target-Environment': self.target_environment,
            'Content-Type': 'application/json',
            'Ocp-Apim-Subscription-Key': self.subscription_key,
            'X-Reference-Id': str(reference_id),
        }
        payload = {
            'amount': str(amount),
            'currency': currency,
            'externalId': str(uuid.uuid4().int)[:8],
            'payer': {'partyIdType': 'MSISDN', 'partyId': phone},
            'payerMessage': 'Payment request',
            'payeeNote': 'Payment from BIM'
        }
        r = requests.post(url, json=payload, headers=headers)
        logger.debug('request_to_pay -> %s', r.status_code)
        if r.status_code == 202:
            # The X-Reference-Id header we sent is the transaction id
            return headers.get('X-Reference-Id')
        logger.error('request_to_pay failed: %s', r.text)
        return None
