"""
IP Tracking Middleware

This module contains middleware for:
- Task 0: Logging request details (IP, timestamp, path)
- Task 1: Blocking requests from blacklisted IPs
- Task 2: Adding geolocation data to request logs
"""

import logging
from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """
    Extract the client IP address from the request.
    Handles proxy headers (X-Forwarded-For, X-Real-IP) for requests
    coming through load balancers or reverse proxies.
    
    Uses django-ipware if available for more reliable IP detection.
    """
    try:
        # Try to use django-ipware if installed (more reliable)
        from ipware import get_client_ip as ipware_get_client_ip
        ip, is_routable = ipware_get_client_ip(request)
        if ip:
            return ip
    except ImportError:
        pass
    
    # Fallback: Manual IP extraction
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs; the first is the client
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        x_real_ip = request.META.get('HTTP_X_REAL_IP')
        if x_real_ip:
            ip = x_real_ip.strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    
    return ip


def get_geolocation(ip_address):
    """
    Get geolocation data for an IP address.
    Results are cached for 24 hours to reduce API calls.
    
    Task 2: IP Geolocation Analytics
    
    Returns:
        dict: {'country': str, 'city': str} or empty dict on failure
    """
    # Check cache first (24 hour cache)
    cache_key = f'geo_{ip_address}'
    cached_data = cache.get(cache_key)
    if cached_data is not None:
        return cached_data
    
    geo_data = {'country': None, 'city': None}
    
    try:
        # Try django-ipgeolocation if installed
        from django_ipgeolocation.models import IPLocation
        location = IPLocation(ip_address)
        geo_data = {
            'country': getattr(location, 'country', None),
            'city': getattr(location, 'city', None),
        }
    except ImportError:
        # Fallback: Try using requests with ip-api.com (free, no API key)
        try:
            import requests
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    geo_data = {
                        'country': data.get('country'),
                        'city': data.get('city'),
                    }
        except Exception as e:
            logger.warning(f"Geolocation lookup failed for {ip_address}: {e}")
    except Exception as e:
        logger.warning(f"Geolocation lookup failed for {ip_address}: {e}")
    
    # Cache for 24 hours (86400 seconds)
    cache.set(cache_key, geo_data, 86400)
    
    return geo_data


def is_ip_blocked(ip_address):
    """
    Check if an IP address is in the blacklist.
    Uses caching for performance.
    
    Task 1: IP Blacklisting
    """
    # Check cache first for faster lookups
    cache_key = f'blocked_{ip_address}'
    is_blocked = cache.get(cache_key)
    
    if is_blocked is not None:
        return is_blocked
    
    # Check database
    from .models import BlockedIP
    is_blocked = BlockedIP.objects.filter(
        ip_address=ip_address,
        is_active=True
    ).exists()
    
    # Cache the result for 5 minutes
    cache.set(cache_key, is_blocked, 300)
    
    return is_blocked


class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware to track IP addresses and log request details.
    
    This middleware:
    1. Checks if the IP is blacklisted (Task 1)
    2. Logs request details to the database (Task 0)
    3. Adds geolocation data to logs (Task 2)
    
    Order of operations:
    - First checks blacklist (returns 403 if blocked)
    - Then logs the request with geolocation data
    """
    
    def process_request(self, request):
        """
        Process incoming request:
        1. Extract client IP
        2. Check if IP is blocked
        3. Log the request with geolocation data
        """
        # Get the client's IP address
        ip_address = get_client_ip(request)
        
        # Store IP on request object for use in views
        request.client_ip = ip_address
        
        # Task 1: Check if IP is blacklisted
        if is_ip_blocked(ip_address):
            logger.warning(f"Blocked request from blacklisted IP: {ip_address}")
            return HttpResponseForbidden(
                "Access Denied: Your IP address has been blocked."
            )
        
        # Task 0 & 2: Log the request with geolocation
        self._log_request(request, ip_address)
        
        return None
    
    def _log_request(self, request, ip_address):
        """
        Log the request to the database.
        
        Task 0: Basic logging (IP, timestamp, path)
        Task 2: Add geolocation (country, city)
        """
        from .models import RequestLog
        
        # Get geolocation data (Task 2)
        geo_data = get_geolocation(ip_address)
        
        try:
            RequestLog.objects.create(
                ip_address=ip_address,
                path=request.path,
                country=geo_data.get('country'),
                city=geo_data.get('city'),
            )
        except Exception as e:
            # Don't let logging failures break the request
            logger.error(f"Failed to log request from {ip_address}: {e}")


class IPBlockMiddleware(MiddlewareMixin):
    """
    Alternative lightweight middleware that only checks for blocked IPs.
    Use this if you want to separate blocking from logging.
    
    Task 1: IP Blacklisting (standalone version)
    """
    
    def process_request(self, request):
        """Check if the request IP is blocked."""
        ip_address = get_client_ip(request)
        request.client_ip = ip_address
        
        if is_ip_blocked(ip_address):
            logger.warning(f"Blocked request from blacklisted IP: {ip_address}")
            return HttpResponseForbidden(
                "Access Denied: Your IP address has been blocked."
            )
        
        return None


class IPLoggingMiddleware(MiddlewareMixin):
    """
    Alternative middleware that only logs requests.
    Use this if you want to separate logging from blocking.
    
    Task 0: Basic IP Logging (standalone version)
    Task 2: IP Geolocation (standalone version)
    """
    
    def process_request(self, request):
        """Log the request details."""
        from .models import RequestLog
        
        ip_address = get_client_ip(request)
        request.client_ip = ip_address
        
        # Get geolocation data
        geo_data = get_geolocation(ip_address)
        
        try:
            RequestLog.objects.create(
                ip_address=ip_address,
                path=request.path,
                country=geo_data.get('country'),
                city=geo_data.get('city'),
            )
        except Exception as e:
            logger.error(f"Failed to log request from {ip_address}: {e}")
        
        return None
