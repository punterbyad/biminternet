from django.db import models


class MoMoTransaction(models.Model):
    """Local model for MoMo transactions to avoid colliding with existing
    Transaction models elsewhere in the project.
    """
    reference = models.CharField(max_length=100, unique=True)
    external_id = models.CharField(max_length=100, blank=True, null=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=10, default='EUR')
    phone = models.CharField(max_length=32)
    email = models.EmailField(blank=True, null=True)
    status = models.CharField(max_length=32, default='created')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"MoMoTransaction {self.reference} ({self.status})"
