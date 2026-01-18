"""
Django Settings Configuration for IP Tracking

This file contains all the settings configurations needed for the IP tracking system.
Copy the relevant sections to your project's settings.py file.

Tasks configured:
- Task 0: Middleware registration for IP logging
- Task 1: Middleware registration for IP blocking
- Task 2: Geolocation configuration
- Task 3: Rate limiting configuration
- Task 4: Celery configuration for anomaly detection
"""

import os
from pathlib import Path

# =============================================================================
# BASE SETTINGS (Standard Django)
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'your-secret-key-here')

DEBUG = os.environ.get('DEBUG', 'True') == 'True'

ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')


# =============================================================================
# INSTALLED APPS
# =============================================================================

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party apps
    'django_ratelimit',  # Task 3: Rate limiting
    # 'django_ipgeolocation',  # Task 2: Geolocation (optional)
    
    # Local apps
    'ip_tracking',
]


# =============================================================================
# MIDDLEWARE CONFIGURATION
# Task 0: IP Logging Middleware
# Task 1: IP Blacklisting Middleware
# Task 2: Geolocation is handled within the middleware
# =============================================================================

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    
    # IP Tracking Middleware - Add this AFTER authentication middleware
    # This combined middleware handles both logging and blocking
    'ip_tracking.middleware.IPTrackingMiddleware',
    
    # Alternative: Use separate middleware classes
    # 'ip_tracking.middleware.IPBlockMiddleware',  # Just blocking
    # 'ip_tracking.middleware.IPLoggingMiddleware',  # Just logging
]


# =============================================================================
# DATABASE
# =============================================================================

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# For production, use PostgreSQL:
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': os.environ.get('DB_NAME', 'ip_tracking'),
#         'USER': os.environ.get('DB_USER', 'postgres'),
#         'PASSWORD': os.environ.get('DB_PASSWORD', ''),
#         'HOST': os.environ.get('DB_HOST', 'localhost'),
#         'PORT': os.environ.get('DB_PORT', '5432'),
#     }
# }


# =============================================================================
# CACHING CONFIGURATION
# Used for:
# - Task 1: Caching blocked IP lookups
# - Task 2: Caching geolocation results
# - Task 3: Rate limiting (if using Redis backend)
# =============================================================================

# Development: In-memory cache
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# Production: Redis cache (recommended)
# CACHES = {
#     'default': {
#         'BACKEND': 'django.core.cache.backends.redis.RedisCache',
#         'LOCATION': os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/1'),
#     }
# }


# =============================================================================
# TASK 2: GEOLOCATION CONFIGURATION
# =============================================================================

# Option 1: Using django-ipgeolocation
# Install: pip install django-ipgeolocation
# IPGEOLOCATION_API_KEY = os.environ.get('IPGEOLOCATION_API_KEY', '')

# Option 2: Using ipinfo.io
# IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN', '')

# Option 3: Using MaxMind GeoIP2 database (offline)
# Download database from: https://dev.maxmind.com/geoip/geoip2/geolite2/
# GEOIP_PATH = os.path.join(BASE_DIR, 'geoip')


# =============================================================================
# TASK 3: RATE LIMITING CONFIGURATION
# =============================================================================

# django-ratelimit settings
RATELIMIT_USE_CACHE = 'default'
RATELIMIT_ENABLE = True

# Custom rate limit view handler
RATELIMIT_VIEW = 'ip_tracking.views.rate_limit_exceeded'

# Rate limits (these are applied in the views)
# - Anonymous users: 5 requests per minute
# - Authenticated users: 10 requests per minute


# =============================================================================
# TASK 4: CELERY CONFIGURATION
# =============================================================================

# Celery Broker URL (Redis recommended)
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://127.0.0.1:6379/0')

# Celery Result Backend
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://127.0.0.1:6379/0')

# Celery timezone
CELERY_TIMEZONE = 'UTC'

# Celery task serialization
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']

# Celery Beat Schedule (for periodic tasks)
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    # Task 4: Run anomaly detection every hour
    'detect-anomalies-hourly': {
        'task': 'ip_tracking.tasks.detect_anomalies',
        'schedule': crontab(minute=0),  # Run at the start of every hour
    },
    
    # Cleanup old request logs daily at 3 AM
    'cleanup-old-logs-daily': {
        'task': 'ip_tracking.tasks.cleanup_old_logs',
        'schedule': crontab(hour=3, minute=0),
        'kwargs': {'days': 30},
    },
    
    # Cleanup old suspicious IP records weekly on Sunday at 4 AM
    'cleanup-suspicious-ips-weekly': {
        'task': 'ip_tracking.tasks.cleanup_old_suspicious_ips',
        'schedule': crontab(hour=4, minute=0, day_of_week=0),
        'kwargs': {'days': 90},
    },
    
    # Auto-block repeat offenders daily at 5 AM
    'auto-block-suspicious-daily': {
        'task': 'ip_tracking.tasks.auto_block_suspicious_ips',
        'schedule': crontab(hour=5, minute=0),
        'kwargs': {'threshold': 3},
    },
}


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'ip_tracking.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'ip_tracking': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}


# =============================================================================
# OTHER STANDARD DJANGO SETTINGS
# =============================================================================

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
