"""
Dark Knight Phantom SIEM - Django Settings
Enterprise Security Information and Event Management System
"""

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'dkp-siem-secret-key-change-in-production-x7k9m2n4p6q8r0s3t5v7w9y1z3'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party apps
    'rest_framework',
    'corsheaders',
    
    # Dark Knight Phantom SIEM Apps
    'apps.events',
    'apps.agents',
    'apps.alerts',
    'apps.query',
    'apps.dashboard',
    'apps.detection',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # CSRF disabled for lab environment
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Disable CSRF for lab environment
CSRF_TRUSTED_ORIGINS = ['http://*', 'https://*']

ROOT_URLCONF = 'dark_knight_phantom.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
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

WSGI_APPLICATION = 'dark_knight_phantom.wsgi.application'

# Database - PostgreSQL Only
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'dark_knight_phantom',
        'USER': 'root',
        'PASSWORD': 'admin',
        'HOST': 'localhost',
        'PORT': '5432',
        'OPTIONS': {
            'connect_timeout': 10,
        },
        'CONN_MAX_AGE': 600,
    }
}

# Password validation - Disabled for lab
AUTH_PASSWORD_VALIDATORS = []

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# CORS Settings
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# Django REST Framework Settings - No Auth for Lab
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [],  # No authentication for lab
    'DEFAULT_FILTER_BACKENDS': [
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 100,
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'UNAUTHENTICATED_USER': None,
}

# Dark Knight Phantom SIEM Settings
PHANTOM_SIEM = {
    'AGENT_HEARTBEAT_INTERVAL': 30,  # seconds
    'EVENT_BATCH_SIZE': 1000,
    'MAX_EVENTS_PER_REQUEST': 5000,
    'EVENT_RETENTION_DAYS': 90,
    'ALERT_SEVERITY_LEVELS': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    'THEME': {
        'PRIMARY_COLOR': '#1a1a2e',      # Dark navy
        'SECONDARY_COLOR': '#16213e',     # Dark blue
        'ACCENT_COLOR': '#6c5ce7',        # Purple
        'ACCENT_SECONDARY': '#0984e3',    # Blue
        'DANGER_COLOR': '#d63031',        # Red
        'WARNING_COLOR': '#fdcb6e',       # Yellow
        'SUCCESS_COLOR': '#00b894',       # Green
        'TEXT_PRIMARY': '#ffffff',        # White
        'TEXT_SECONDARY': '#a0a0a0',      # Gray
        'BACKGROUND_DARK': '#0f0f1a',     # Darkest
        'BACKGROUND_CARD': '#1a1a2e',     # Card background
        'BORDER_COLOR': '#2d2d44',        # Border
    }
}

# Logging Configuration
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
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'apps': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}

