import requests
import re
import os
import logging

logger = logging.getLogger(__name__)


class EgoSMSService:
    BASE_URL = "https://www.egosms.co/api/v1/json/"

    def __init__(self, username=None, password=None, sender="BIM-INTERNET"):
        # Prefer explicit args, then Django settings, then environment variables
        django_user = None
        django_pass = None
        try:
            # Import locally to avoid requiring Django at module import time
            from django.conf import settings as django_settings
            django_user = getattr(django_settings, 'EGOSMS_USER', None)
            django_pass = getattr(django_settings, 'EGOSMS_PASS', None)
        except Exception:
            # not running inside Django or settings not configured
            django_user = None
            django_pass = None

        self.username = username or django_user or os.getenv("EGOSMS_USER")
        self.password = password or django_pass or os.getenv("EGOSMS_PASS")
        self.sender = sender

    def format_phone_number(self, phone: str, country_code="256") -> str:
        cleaned = re.sub(r"\D", "", phone)
        if cleaned.startswith(country_code):
            return cleaned
        if cleaned.startswith("0"):
            return country_code + cleaned[1:]
        return country_code + cleaned

    def send_sms(self, number: str, message: str) -> bool:
        phone = self.format_phone_number(number)
        data = {
            "method": "SendSms",
            "userdata": {
                "username": self.username,
                "password": self.password,
            },
            "msgdata": [{
                "number": phone,
                "message": message,
                "senderid": self.sender,
            }],
        }

        try:
            response = requests.post(self.BASE_URL, json=data, headers={"Content-Type": "application/json"}, timeout=10)
        except Exception as exc:
            logger.exception("EgoSMS HTTP request failed for %s: %s", phone, exc)
            return False

        try:
            result = response.json()
        except Exception:
            # Log the raw response body to help debugging
            logger.error("EgoSMS returned non-JSON response (status=%s) for %s: %s", getattr(response, 'status_code', 'n/a'), phone, getattr(response, 'text', ''))
            return False

        if response.status_code != 200 or result.get("Status") != "OK":
            logger.error("EgoSMS send failed (status=%s) for %s: %s", response.status_code, phone, result)
            return False

        return True

    def send_otp(self, phone: str, otp: str) -> bool:
        return self.send_sms(phone, f"Your Access Key is: {otp}")
