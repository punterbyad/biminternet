

import subprocess
import json
import uuid
import logging
from django.conf import settings
from core.models import Router, Transaction, TransactionStatus
from django.db import models

class PaytotaService:
    def __init__(self):
        self.base_url = getattr(settings, 'PAYTOTA_BASEURL', '')
        self.brand_id = getattr(settings, 'PAYTOTA_BRANDID', '')
        self.bearer_token = getattr(settings, 'PAYTOTA_SECRET_KEY', '')

    def format_phone_number(self, phone, country_code='256'):
        cleaned = ''.join(filter(str.isdigit, phone))
        if cleaned.startswith(country_code):
            return cleaned
        if cleaned.startswith('0'):
            return country_code + cleaned[1:]
        return cleaned

    def update_router_balance(self, router_id):
        balance = Transaction.objects.filter(router_id=router_id).aggregate(total=models.Sum('amount'))['total'] or 0
        Router.objects.filter(id=router_id).update(balance=balance)

    def send_sms(self, number, message):
        phone = self.format_phone_number(number)
        try:
            subprocess.run([
                'curl',
                '-G',
                'http://panel.smspm.com/gateway/122a0035aa15c2d72306f0d2d6a994e75f8c16dc/api.v1/send',
                '--data-urlencode', f'phone={phone}',
                '--data-urlencode', f'message={message}',
                '--data-urlencode', 'sender=BIM-INTERNET'
            ], check=True)
        except Exception as e:
            logging.error(f"SMS sending failed: {e}")

    def get_payment_method(self, phone):
        phone = self.format_phone_number(phone)
        if phone.startswith('25670') or phone.startswith('25674') or phone.startswith('25675'):
            return 'airtel'
        elif phone.startswith('25676') or phone.startswith('25677') or phone.startswith('25678'):
            return 'mtnmomo'
        return ''

    def initiate_transaction(self, amount, phone, router_id):
        router = Router.objects.filter(id=router_id).first()
        if not router:
            raise Exception(f"Router with id '{router_id}' not found")
        Transaction.objects.create(
            router_id=router_id,
            type='credit',
            amount=amount,
            reason='Customer initiated credit',
            status='successful',
        )
        # Transaction charge
        if amount <= 1000:
            debit_amount = -(amount * 0.15)
        elif amount > 1000 and amount <= 5000:
            debit_amount = -(amount * 0.10)
        else:
            debit_amount = -(amount * 0.05)
        Transaction.objects.create(
            router_id=router_id,
            type='debit',
            amount=debit_amount,
            reason='Transaction Charge',
            status='successful',
        )
        self.update_router_balance(router_id)
        return True

    def initiate(self, amount, phone, router_id, email=None, description='BIM INTERNET'):
        reference = str(uuid.uuid4())
        TransactionStatus.objects.create(
            reference=reference,
            router_id=router_id,
            phone=self.format_phone_number(phone),
            email=email,
            status='created',
        )
        payment_method = self.get_payment_method(phone)
        if not payment_method:
            raise Exception('Unsupported carrier. Please review the phone number and try again')
        transaction_data = {
            'client': {
                'email': email,
                'phone': self.format_phone_number(phone),
            },
            'purchase': {
                'currency': 'UGX',
                'products': [
                    {'name': description, 'price': amount},
                ],
            },
            'reference': reference,
            'skip_capture': False,
            'brand_id': self.brand_id,
            'payment_method_whitelist': ['airtel', 'mtnmomo'],
        }
        try:
            curl_cmd = [
                'curl', '-X', 'POST',
                f'{self.base_url}/api/v1/purchases/',
                '-H', f'Authorization: Bearer {self.bearer_token}',
                '-H', 'Content-Type: application/json',
                '-d', json.dumps(transaction_data)
            ]
            result = subprocess.run(curl_cmd, capture_output=True, text=True, check=True)
            response = json.loads(result.stdout)
            if 'error' in response:
                raise Exception(f"Transaction initiation failed: {response['error']}")
            return response
        except Exception as e:
            logging.error(f"Paytota initiate failed: {e}")
            raise

    def execute(self, reference, amount, phone, router_id):
        # Example execute logic using curl
        execute_data = {
            'reference': reference,
            'amount': amount,
            'phone': self.format_phone_number(phone),
            'router_id': str(router_id),
        }
        try:
            curl_cmd = [
                'curl', '-X', 'POST',
                f'{self.base_url}/api/v1/execute/',
                '-H', f'Authorization: Bearer {self.bearer_token}',
                '-H', 'Content-Type: application/json',
                '-d', json.dumps(execute_data)
            ]
            result = subprocess.run(curl_cmd, capture_output=True, text=True, check=True)
            response = json.loads(result.stdout)
            if 'error' in response:
                raise Exception(f"Transaction execution failed: {response['error']}")
            return response
        except Exception as e:
            logging.error(f"Paytota execute failed: {e}")
            raise

    def callback(self, reference, status, details=None):
        # Example callback logic
        try:
            ts = TransactionStatus.objects.filter(reference=reference).first()
            if not ts:
                raise Exception(f"TransactionStatus with reference {reference} not found")
            ts.status = status
            if details:
                ts.status_history.append(details)
            ts.save()
            return True
        except Exception as e:
            logging.error(f"Callback failed: {e}")
            return False

    def get_status(self, reference):
        ts = TransactionStatus.objects.filter(reference=reference).first()
        if not ts:
            return None
        return ts.status

    def get_transaction(self, reference):
        return TransactionStatus.objects.filter(reference=reference).first()

    def refund(self, reference, amount):
        # Example refund logic using curl
        refund_data = {
            'reference': reference,
            'amount': amount,
        }
        try:
            curl_cmd = [
                'curl', '-X', 'POST',
                f'{self.base_url}/api/v1/refund/',
                '-H', f'Authorization: Bearer {self.bearer_token}',
                '-H', 'Content-Type: application/json',
                '-d', json.dumps(refund_data)
            ]
            result = subprocess.run(curl_cmd, capture_output=True, text=True, check=True)
            response = json.loads(result.stdout)
            if 'error' in response:
                raise Exception(f"Refund failed: {response['error']}")
            return response
        except Exception as e:
            logging.error(f"Paytota refund failed: {e}")
            raise
