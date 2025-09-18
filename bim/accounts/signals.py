from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
User = get_user_model()


@receiver(post_save, sender=User)
def ensure_tenant_on_create(sender, instance, created, **kwargs):
    """
    Previously this created a Kill Bill tenant and default account asynchronously.
    Kill Bill integration removed; keep a safe no-op so existing migrations and
    code paths that relied on this signal don't fail.
    """
    if not created:
        return

    # If optional api_key/api_secret fields exist, leave them alone.
    # Otherwise, ensure migrations won't fail by not attempting remote calls.
    return
