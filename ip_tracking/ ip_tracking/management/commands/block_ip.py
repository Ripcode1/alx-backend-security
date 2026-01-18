"""
Management command to add IPs to the blacklist.

Task 1: IP Blacklisting

Usage:
    python manage.py block_ip 192.168.1.1
    python manage.py block_ip 192.168.1.1 --reason "Suspicious activity"
    python manage.py block_ip 192.168.1.1 192.168.1.2 192.168.1.3
    python manage.py block_ip 192.168.1.0/24 --subnet  # Block entire subnet
    python manage.py block_ip 192.168.1.1 --unblock  # Remove from blacklist
    python manage.py block_ip --list  # List all blocked IPs
"""

from django.core.management.base import BaseCommand, CommandError
from django.core.cache import cache
from django.utils import timezone
import ipaddress


class Command(BaseCommand):
    help = 'Manage IP blacklist - add, remove, or list blocked IPs'
    
    def add_arguments(self, parser):
        # Positional arguments - IP addresses to block
        parser.add_argument(
            'ip_addresses',
            nargs='*',
            type=str,
            help='IP address(es) to block'
        )
        
        # Optional arguments
        parser.add_argument(
            '--reason',
            '-r',
            type=str,
            default='Blocked via management command',
            help='Reason for blocking the IP(s)'
        )
        
        parser.add_argument(
            '--unblock',
            '-u',
            action='store_true',
            help='Remove IP(s) from the blacklist instead of adding'
        )
        
        parser.add_argument(
            '--list',
            '-l',
            action='store_true',
            help='List all currently blocked IPs'
        )
        
        parser.add_argument(
            '--subnet',
            '-s',
            action='store_true',
            help='Treat IP as a subnet (e.g., 192.168.1.0/24) and block all IPs in it'
        )
        
        parser.add_argument(
            '--deactivate',
            '-d',
            action='store_true',
            help='Deactivate the block instead of deleting (for unblock)'
        )
        
        parser.add_argument(
            '--clear-cache',
            '-c',
            action='store_true',
            help='Clear the cache for blocked IPs after modification'
        )
    
    def handle(self, *args, **options):
        from ip_tracking.models import BlockedIP
        
        # List all blocked IPs
        if options['list']:
            return self.list_blocked_ips()
        
        # Validate that IP addresses were provided
        if not options['ip_addresses']:
            raise CommandError(
                'Please provide at least one IP address, or use --list to see blocked IPs'
            )
        
        # Process each IP address
        for ip_input in options['ip_addresses']:
            if options['subnet']:
                self.process_subnet(ip_input, options)
            else:
                self.process_single_ip(ip_input, options)
        
        # Clear cache if requested
        if options['clear_cache']:
            self.clear_blocked_ip_cache(options['ip_addresses'])
    
    def process_single_ip(self, ip_address, options):
        """Process a single IP address."""
        from ip_tracking.models import BlockedIP
        
        # Validate IP address format
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            self.stderr.write(
                self.style.ERROR(f'Invalid IP address format: {ip_address}')
            )
            return
        
        if options['unblock']:
            self.unblock_ip(ip_address, options['deactivate'])
        else:
            self.block_ip(ip_address, options['reason'])
        
        # Clear cache for this IP
        cache_key = f'blocked_{ip_address}'
        cache.delete(cache_key)
    
    def process_subnet(self, subnet_str, options):
        """Process a subnet and block all IPs in it."""
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
        except ValueError as e:
            self.stderr.write(
                self.style.ERROR(f'Invalid subnet format: {subnet_str} - {e}')
            )
            return
        
        # Limit subnet size to prevent accidental mass blocking
        if network.num_addresses > 256:
            self.stderr.write(
                self.style.WARNING(
                    f'Subnet {subnet_str} contains {network.num_addresses} addresses. '
                    f'Only /24 or smaller subnets are allowed for safety.'
                )
            )
            return
        
        self.stdout.write(
            f'Processing {network.num_addresses} addresses in subnet {subnet_str}...'
        )
        
        count = 0
        for ip in network.hosts():
            ip_str = str(ip)
            if options['unblock']:
                if self.unblock_ip(ip_str, options['deactivate'], quiet=True):
                    count += 1
            else:
                if self.block_ip(ip_str, options['reason'], quiet=True):
                    count += 1
            
            # Clear cache
            cache.delete(f'blocked_{ip_str}')
        
        action = 'unblocked' if options['unblock'] else 'blocked'
        self.stdout.write(
            self.style.SUCCESS(f'Successfully {action} {count} IPs from subnet {subnet_str}')
        )
    
    def block_ip(self, ip_address, reason, quiet=False):
        """Add an IP to the blacklist."""
        from ip_tracking.models import BlockedIP
        
        # Check if already blocked
        existing = BlockedIP.objects.filter(ip_address=ip_address).first()
        
        if existing:
            if existing.is_active:
                if not quiet:
                    self.stdout.write(
                        self.style.WARNING(f'IP {ip_address} is already blocked')
                    )
                return False
            else:
                # Reactivate existing block
                existing.is_active = True
                existing.reason = reason
                existing.save()
                if not quiet:
                    self.stdout.write(
                        self.style.SUCCESS(f'Reactivated block for IP: {ip_address}')
                    )
                return True
        
        # Create new block
        BlockedIP.objects.create(
            ip_address=ip_address,
            reason=reason,
        )
        
        if not quiet:
            self.stdout.write(
                self.style.SUCCESS(f'Successfully blocked IP: {ip_address}')
            )
        return True
    
    def unblock_ip(self, ip_address, deactivate=False, quiet=False):
        """Remove an IP from the blacklist."""
        from ip_tracking.models import BlockedIP
        
        try:
            blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
            
            if deactivate:
                blocked_ip.is_active = False
                blocked_ip.save()
                if not quiet:
                    self.stdout.write(
                        self.style.SUCCESS(f'Deactivated block for IP: {ip_address}')
                    )
            else:
                blocked_ip.delete()
                if not quiet:
                    self.stdout.write(
                        self.style.SUCCESS(f'Removed IP from blacklist: {ip_address}')
                    )
            return True
            
        except BlockedIP.DoesNotExist:
            if not quiet:
                self.stdout.write(
                    self.style.WARNING(f'IP {ip_address} is not in the blacklist')
                )
            return False
    
    def list_blocked_ips(self):
        """List all blocked IPs."""
        from ip_tracking.models import BlockedIP
        
        blocked_ips = BlockedIP.objects.all().order_by('-created_at')
        
        if not blocked_ips.exists():
            self.stdout.write('No IPs are currently blocked.')
            return
        
        self.stdout.write(self.style.SUCCESS(f'\nBlocked IPs ({blocked_ips.count()} total):'))
        self.stdout.write('-' * 80)
        
        for ip in blocked_ips:
            status = self.style.SUCCESS('ACTIVE') if ip.is_active else self.style.WARNING('INACTIVE')
            self.stdout.write(
                f'{ip.ip_address:20} | {status:20} | {ip.created_at.strftime("%Y-%m-%d %H:%M")}'
            )
            if ip.reason:
                self.stdout.write(f'    Reason: {ip.reason}')
        
        self.stdout.write('-' * 80)
        
        active_count = blocked_ips.filter(is_active=True).count()
        self.stdout.write(f'Active: {active_count}, Inactive: {blocked_ips.count() - active_count}')
    
    def clear_blocked_ip_cache(self, ip_addresses):
        """Clear the cache for specified IPs."""
        for ip in ip_addresses:
            try:
                # Handle subnet
                if '/' in ip:
                    network = ipaddress.ip_network(ip, strict=False)
                    for host_ip in network.hosts():
                        cache.delete(f'blocked_{host_ip}')
                else:
                    cache.delete(f'blocked_{ip}')
            except ValueError:
                pass
        
        self.stdout.write(self.style.SUCCESS('Cache cleared for blocked IPs'))
