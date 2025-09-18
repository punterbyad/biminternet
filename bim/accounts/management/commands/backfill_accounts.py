from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from accounts.models import Account, AccountMembership


class Command(BaseCommand):
    help = "Create owner Account and AccountMembership for specified user UUIDs (idempotent)."

    def add_arguments(self, parser):
        parser.add_argument('pks', nargs='*', help='User primary keys (UUID) to backfill')

    def handle(self, *args, **options):
        User = get_user_model()
        pks = options.get('pks') or []

        if not pks:
            self.stdout.write(self.style.ERROR('No user pks provided.'))
            return 1

        for pk in pks:
            try:
                u = User.objects.get(pk=pk)
            except User.DoesNotExist:
                self.stdout.write(self.style.WARNING(f'User not found: {pk}'))
                continue

            acct, acct_created = Account.objects.get_or_create(
                owner=u,
                defaults={'name': f"{u.first_name or u.email or 'Account'}'s Account"}
            )

            mem, mem_created = AccountMembership.objects.get_or_create(
                account=acct,
                user=u,
                role='owner',
                defaults={'invited_by': u, 'invitation_email': u.email or '', 'accepted': True}
            )

            self.stdout.write(
                f"User {getattr(u,'email', None)} - account {acct.id} - account_created={acct_created} membership_created={mem_created}"
            )

        return 0
