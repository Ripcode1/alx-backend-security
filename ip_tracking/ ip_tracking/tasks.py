"""
IP Tracking Celery Tasks

This module contains Celery tasks for:
- Task 4: Anomaly Detection - detecting suspicious IP activity

The anomaly detection task runs hourly and flags IPs that:
1. Exceed 100 requests per hour
2. Access sensitive paths like /admin or /login
"""

import logging
from datetime import timedelta

from celery import shared_task
from django.utils import timezone
from django.db.models import Count

logger = logging.getLogger(__name__)

# Sensitive paths that trigger anomaly detection
SENSITIVE_PATHS = [
    '/admin',
    '/admin/',
    '/login',
    '/login/',
    '/api/auth',
    '/api/login',
    '/accounts/login',
    '/accounts/login/',
    '/wp-admin',  # Common attack target
    '/wp-login.php',  # Common attack target
    '/.env',  # Common attack target
    '/config',  # Common attack target
]

# Thresholds for anomaly detection
REQUEST_THRESHOLD = 100  # Max requests per hour before flagging
SENSITIVE_PATH_THRESHOLD = 20  # Max sensitive path requests per hour


@shared_task(bind=True, max_retries=3)
def detect_anomalies(self):
    """
    Celery task to detect suspicious IP activity.
    
    Task 4: Anomaly Detection
    
    This task runs hourly and performs the following checks:
    1. Flags IPs that exceed 100 requests in the past hour
    2. Flags IPs that excessively access sensitive paths
    
    Detected anomalies are stored in the SuspiciousIP model.
    """
    from .models import RequestLog, SuspiciousIP
    
    logger.info("Starting anomaly detection task")
    
    # Time window: last hour
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    try:
        # Detection 1: IPs exceeding request threshold
        high_volume_ips = detect_high_volume_ips(one_hour_ago)
        
        # Detection 2: IPs accessing sensitive paths excessively
        sensitive_path_ips = detect_sensitive_path_access(one_hour_ago)
        
        # Combine and deduplicate flagged IPs
        flagged_ips = {}
        
        for ip, count in high_volume_ips.items():
            flagged_ips[ip] = {
                'reasons': [f'Exceeded {REQUEST_THRESHOLD} requests/hour ({count} requests)'],
                'request_count': count,
            }
        
        for ip, data in sensitive_path_ips.items():
            if ip in flagged_ips:
                flagged_ips[ip]['reasons'].append(
                    f'Excessive sensitive path access: {data["paths"]}'
                )
            else:
                flagged_ips[ip] = {
                    'reasons': [f'Excessive sensitive path access: {data["paths"]}'],
                    'request_count': data['count'],
                }
        
        # Create SuspiciousIP records
        created_count = 0
        for ip, data in flagged_ips.items():
            reason = '; '.join(data['reasons'])
            
            # Check if this IP was already flagged recently (within last 24 hours)
            recent_flag = SuspiciousIP.objects.filter(
                ip_address=ip,
                detected_at__gte=timezone.now() - timedelta(hours=24)
            ).exists()
            
            if not recent_flag:
                SuspiciousIP.objects.create(
                    ip_address=ip,
                    reason=reason,
                    request_count=data['request_count'],
                )
                created_count += 1
                logger.warning(f"Flagged suspicious IP: {ip} - {reason}")
        
        logger.info(
            f"Anomaly detection complete. "
            f"Flagged {created_count} new suspicious IPs."
        )
        
        return {
            'status': 'success',
            'flagged_count': created_count,
            'total_analyzed': len(flagged_ips),
        }
        
    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
        raise self.retry(exc=e, countdown=60)


def detect_high_volume_ips(since_time):
    """
    Detect IPs that have made too many requests.
    
    Args:
        since_time: datetime - Start of the time window
        
    Returns:
        dict: {ip_address: request_count} for IPs exceeding threshold
    """
    from .models import RequestLog
    
    # Group requests by IP and count
    ip_counts = RequestLog.objects.filter(
        timestamp__gte=since_time
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(
        request_count__gt=REQUEST_THRESHOLD
    )
    
    return {
        item['ip_address']: item['request_count']
        for item in ip_counts
    }


def detect_sensitive_path_access(since_time):
    """
    Detect IPs that are excessively accessing sensitive paths.
    
    Args:
        since_time: datetime - Start of the time window
        
    Returns:
        dict: {ip_address: {'count': int, 'paths': list}} for flagged IPs
    """
    from .models import RequestLog
    from django.db.models import Q
    
    # Build query for sensitive paths
    path_query = Q()
    for path in SENSITIVE_PATHS:
        path_query |= Q(path__startswith=path)
    
    # Find IPs accessing sensitive paths
    sensitive_access = RequestLog.objects.filter(
        timestamp__gte=since_time
    ).filter(path_query).values(
        'ip_address', 'path'
    ).annotate(
        count=Count('id')
    ).filter(
        count__gt=SENSITIVE_PATH_THRESHOLD
    )
    
    # Aggregate by IP
    result = {}
    for item in sensitive_access:
        ip = item['ip_address']
        if ip not in result:
            result[ip] = {'count': 0, 'paths': []}
        result[ip]['count'] += item['count']
        if item['path'] not in result[ip]['paths']:
            result[ip]['paths'].append(item['path'])
    
    return result


@shared_task
def cleanup_old_logs(days=30):
    """
    Cleanup task to remove old request logs.
    
    This helps maintain database performance and comply with
    data retention policies.
    
    Args:
        days: int - Delete logs older than this many days
    """
    from .models import RequestLog
    
    cutoff_date = timezone.now() - timedelta(days=days)
    
    deleted_count, _ = RequestLog.objects.filter(
        timestamp__lt=cutoff_date
    ).delete()
    
    logger.info(f"Deleted {deleted_count} request logs older than {days} days")
    
    return {'deleted_count': deleted_count}


@shared_task
def cleanup_old_suspicious_ips(days=90):
    """
    Cleanup task to remove old suspicious IP records that have been reviewed.
    
    Args:
        days: int - Delete reviewed records older than this many days
    """
    from .models import SuspiciousIP
    
    cutoff_date = timezone.now() - timedelta(days=days)
    
    deleted_count, _ = SuspiciousIP.objects.filter(
        detected_at__lt=cutoff_date,
        is_reviewed=True
    ).delete()
    
    logger.info(
        f"Deleted {deleted_count} reviewed suspicious IP records "
        f"older than {days} days"
    )
    
    return {'deleted_count': deleted_count}


@shared_task
def auto_block_suspicious_ips(threshold=3):
    """
    Automatically block IPs that have been flagged multiple times.
    
    Args:
        threshold: int - Number of times an IP must be flagged to be auto-blocked
    """
    from .models import SuspiciousIP, BlockedIP
    from django.db.models import Count
    
    # Find IPs flagged multiple times
    repeat_offenders = SuspiciousIP.objects.values(
        'ip_address'
    ).annotate(
        flag_count=Count('id')
    ).filter(
        flag_count__gte=threshold
    )
    
    blocked_count = 0
    for item in repeat_offenders:
        ip = item['ip_address']
        
        # Check if already blocked
        if not BlockedIP.objects.filter(ip_address=ip).exists():
            BlockedIP.objects.create(
                ip_address=ip,
                reason=f'Auto-blocked: Flagged {item["flag_count"]} times for suspicious activity',
            )
            blocked_count += 1
            logger.warning(f"Auto-blocked IP: {ip}")
    
    logger.info(f"Auto-blocked {blocked_count} repeat offender IPs")
    
    return {'blocked_count': blocked_count}


# =============================================================================
# Celery Beat Schedule Configuration
# =============================================================================
# Add this to your Django settings.py or celery.py:
#
# from celery.schedules import crontab
#
# CELERY_BEAT_SCHEDULE = {
#     'detect-anomalies-hourly': {
#         'task': 'ip_tracking.tasks.detect_anomalies',
#         'schedule': crontab(minute=0),  # Run at the start of every hour
#     },
#     'cleanup-old-logs-daily': {
#         'task': 'ip_tracking.tasks.cleanup_old_logs',
#         'schedule': crontab(hour=3, minute=0),  # Run at 3 AM daily
#         'kwargs': {'days': 30},
#     },
#     'cleanup-suspicious-ips-weekly': {
#         'task': 'ip_tracking.tasks.cleanup_old_suspicious_ips',
#         'schedule': crontab(hour=4, minute=0, day_of_week=0),  # Sunday 4 AM
#         'kwargs': {'days': 90},
#     },
#     'auto-block-suspicious-daily': {
#         'task': 'ip_tracking.tasks.auto_block_suspicious_ips',
#         'schedule': crontab(hour=5, minute=0),  # Run at 5 AM daily
#         'kwargs': {'threshold': 3},
#     },
# }
