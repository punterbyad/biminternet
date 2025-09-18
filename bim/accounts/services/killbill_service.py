"""Minimal stub to remove external Kill Bill dependency from the project."""
from typing import Any, Dict, List


def get_tenant(api_key: str, api_secret: str, external_key: str) -> Dict[str, Any]:
    return {}


def get_accounts_for_tenant(api_key: str, api_secret: str, external_key: str) -> List[Dict[str, Any]]:
    return []


def get_account_balance(api_key: str, api_secret: str, account_id: str) -> Dict[str, Any]:
    return {"balance": 0}


def get_account_invoices(api_key: str, api_secret: str, account_id: str) -> List[Dict[str, Any]]:
    return []


def init_tenant_and_default_account_async(*, user_id, phone_number, email, country_code: str = "UG", save_callback=None):
    """No-op used in place of the Kill Bill tenant/account bootstrap."""
    if callable(save_callback):
        try:
            save_callback(None, None, None)
        except Exception:
            # swallow exceptions from callbacks to keep stub safe
            pass


def create_account(*args, **kwargs) -> Dict[str, Any]:
    return {"status": "stub"}
