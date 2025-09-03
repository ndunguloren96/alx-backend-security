# alx-backend-security/ip_tracking/management/commands/block_ip.py

from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP
from django.core.cache import cache
import ipaddress

class Command(BaseCommand):
    help = 'Blocks a specified IP address from accessing the site.'

    def add_arguments(self, parser):
        parser.add_argument(
            'ip_address',
            type=str,
            help='The IP address (e.g., "192.168.1.1") to be blocked.'
        )
        parser.add_argument(
            '--reason',
            type=str,
            default='Manual block',
            help='Optional reason for blocking the IP.'
        )

    def handle(self, *args, **options):
        ip_address = options['ip_address']
        reason = options['reason']

        # Validate the IP address format
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            raise CommandError(f'Invalid IP address format: {ip_address}')

        # Add the IP to the database
        try:
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={'reason': reason}
            )
            if created:
                self.stdout.write(self.style.SUCCESS(
                    f'Successfully blocked IP: {ip_address} for reason: "{reason}"'
                ))
            else:
                self.stdout.write(self.style.WARNING(
                    f'IP {ip_address} is already in the blacklist.'
                ))
            
            # Refresh the cache after a new IP is added
            blocked_ips = list(BlockedIP.objects.values_list('ip_address', flat=True))
            cache.set('blocked_ips', blocked_ips, timeout=60 * 60)

        except Exception as e:
            raise CommandError(f'Failed to block IP {ip_address}. Error: {e}')
