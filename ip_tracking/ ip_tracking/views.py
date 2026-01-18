"""
IP Tracking Views

This module contains views with rate limiting.

Task 3: Rate Limiting by IP
- 10 requests/minute for authenticated users
- 5 requests/minute for anonymous users
"""

from django.http import JsonResponse, HttpResponse
from django.views import View
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator

# Import rate limiting decorator
try:
    from django_ratelimit.decorators import ratelimit
    from django_ratelimit.exceptions import Ratelimited
    RATELIMIT_AVAILABLE = True
except ImportError:
    RATELIMIT_AVAILABLE = False
    # Create a dummy decorator if django-ratelimit is not installed
    def ratelimit(*args, **kwargs):
        def decorator(func):
            return func
        return decorator


def get_rate_limit_key(group, request):
    """
    Custom rate limit key function.
    Returns different keys for authenticated vs anonymous users.
    
    This allows different rate limits for different user types.
    """
    if request.user.is_authenticated:
        # Use user ID for authenticated users
        return f'user_{request.user.id}'
    else:
        # Use IP address for anonymous users
        return getattr(request, 'client_ip', request.META.get('REMOTE_ADDR'))


# Rate limit handler for when limit is exceeded
def rate_limit_exceeded(request, exception):
    """
    Custom handler for rate limit exceeded errors.
    Returns a 429 Too Many Requests response.
    """
    return JsonResponse(
        {
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.',
        },
        status=429
    )


# =============================================================================
# Task 3: Rate-Limited Views
# =============================================================================

@ratelimit(key='ip', rate='5/m', method='ALL', block=True)
def login_view_anonymous(request):
    """
    Login view with rate limiting for anonymous users.
    Rate: 5 requests per minute
    
    This is a placeholder login view - in a real application,
    you would implement actual authentication logic here.
    """
    if request.method == 'POST':
        # Placeholder for actual login logic
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        
        # In a real app, you would authenticate here
        # from django.contrib.auth import authenticate, login
        # user = authenticate(request, username=username, password=password)
        
        return JsonResponse({
            'status': 'login_attempt',
            'message': 'Login attempt received (placeholder)',
        })
    
    return JsonResponse({
        'status': 'ok',
        'message': 'Login endpoint (GET)',
        'rate_limit': '5 requests per minute (anonymous)',
    })


@login_required
@ratelimit(key='user', rate='10/m', method='ALL', block=True)
def login_view_authenticated(request):
    """
    Login view with rate limiting for authenticated users.
    Rate: 10 requests per minute
    
    This could be used for session refresh or re-authentication.
    """
    return JsonResponse({
        'status': 'ok',
        'message': f'Authenticated as {request.user.username}',
        'rate_limit': '10 requests per minute (authenticated)',
    })


@ratelimit(key=get_rate_limit_key, rate='5/m', method='ALL', block=True)
@ratelimit(key='user', rate='10/m', method='ALL', block=True)
def login_view(request):
    """
    Combined login view with different rate limits based on authentication.
    
    Uses a custom key function to differentiate between:
    - Anonymous users: 5 requests/minute (by IP)
    - Authenticated users: 10 requests/minute (by user ID)
    
    Task 3: Rate Limiting by IP
    """
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        
        # Placeholder for authentication logic
        return JsonResponse({
            'status': 'login_attempt',
            'message': 'Login attempt received',
            'authenticated': request.user.is_authenticated,
        })
    
    # GET request - show rate limit info
    if request.user.is_authenticated:
        rate_info = '10 requests per minute (authenticated)'
    else:
        rate_info = '5 requests per minute (anonymous)'
    
    return JsonResponse({
        'status': 'ok',
        'endpoint': 'login',
        'rate_limit': rate_info,
        'authenticated': request.user.is_authenticated,
    })


# =============================================================================
# Additional Utility Views
# =============================================================================

def ip_info_view(request):
    """
    View to show the client their IP address and any geolocation data.
    Useful for debugging and testing the IP tracking system.
    """
    from .middleware import get_client_ip, get_geolocation
    
    ip_address = get_client_ip(request)
    geo_data = get_geolocation(ip_address)
    
    return JsonResponse({
        'ip_address': ip_address,
        'country': geo_data.get('country'),
        'city': geo_data.get('city'),
        'is_authenticated': request.user.is_authenticated,
    })


def request_stats_view(request):
    """
    View to show request statistics.
    Admin-only in production.
    """
    from .models import RequestLog, BlockedIP, SuspiciousIP
    from django.db.models import Count
    from django.utils import timezone
    from datetime import timedelta
    
    # Get stats for the last hour
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    # Total requests in last hour
    recent_requests = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).count()
    
    # Top IPs in last hour
    top_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).values('ip_address').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Count of blocked and suspicious IPs
    blocked_count = BlockedIP.objects.filter(is_active=True).count()
    suspicious_count = SuspiciousIP.objects.filter(is_reviewed=False).count()
    
    return JsonResponse({
        'period': 'last_hour',
        'total_requests': recent_requests,
        'top_ips': list(top_ips),
        'blocked_ips_count': blocked_count,
        'suspicious_ips_count': suspicious_count,
    })


# =============================================================================
# Class-Based View Example with Rate Limiting
# =============================================================================

class RateLimitedLoginView(View):
    """
    Class-based login view with rate limiting.
    
    Demonstrates how to apply rate limiting to class-based views.
    """
    
    @method_decorator(ratelimit(key='ip', rate='5/m', method='ALL', block=True))
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)
    
    def get(self, request):
        return JsonResponse({
            'status': 'ok',
            'endpoint': 'login (class-based)',
            'rate_limit': '5 requests per minute',
        })
    
    def post(self, request):
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        
        return JsonResponse({
            'status': 'login_attempt',
            'message': 'Login attempt received (class-based view)',
        })


# =============================================================================
# API Views for Managing IP Tracking
# =============================================================================

@require_http_methods(["GET"])
def blocked_ips_list(request):
    """
    List all blocked IPs.
    Should be restricted to admin users in production.
    """
    from .models import BlockedIP
    
    blocked = BlockedIP.objects.filter(is_active=True).values(
        'ip_address', 'reason', 'created_at'
    )
    
    return JsonResponse({
        'blocked_ips': list(blocked),
        'count': blocked.count(),
    })


@require_http_methods(["GET"])
def suspicious_ips_list(request):
    """
    List suspicious IPs detected by anomaly detection.
    Should be restricted to admin users in production.
    """
    from .models import SuspiciousIP
    
    suspicious = SuspiciousIP.objects.filter(is_reviewed=False).values(
        'ip_address', 'reason', 'detected_at', 'request_count'
    )
    
    return JsonResponse({
        'suspicious_ips': list(suspicious),
        'count': suspicious.count(),
    })
