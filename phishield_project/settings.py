"""
Django settings for phishield_project project.
"""

from pathlib import Path
import os
from django.contrib.messages import constants as messages
from dotenv import load_dotenv
load_dotenv()
import dj_database_url

# Database configuration - automatically handles SSL based on DATABASE_URL
DATABASES = {
    "default": dj_database_url.config(
        default="sqlite:///db.sqlite3",
        conn_max_age=600
        # Removed ssl_require - dj_database_url will handle SSL automatically
        # For Railway/cloud platforms, SSL is typically handled by the connection string
    )
}
# ------------------------------
# Base Directory
# ------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

# ------------------------------
# Security
# ------------------------------
SECRET_KEY = 'django-insecure-6jaqttw(08-+ba(0o+=q#j^tvm&x-97xxpjo$uuzk%$*ad&5qq'
DEBUG = True
ALLOWED_HOSTS = [
    'csit327-g8-phishield-production.up.railway.app',
    '127.0.0.1',
    'localhost',
]
CSRF_TRUSTED_ORIGINS = [
    'https://csit327-g8-phishield-production.up.railway.app',
]




# Security settings for production (commented out for development)
# SECURE_SSL_REDIRECT = True
# SESSION_COOKIE_SECURE = True
# CSRF_COOKIE_SECURE = True
# SECURE_BROWSER_XSS_FILTER = True
# SECURE_CONTENT_TYPE_NOSNIFF = True

# ------------------------------
# Application Definition
# ------------------------------
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Local app
    'phishield',

    # Third-party
    'widget_tweaks',   # For form rendering
    'anymail',         # For SendGrid email API (works on Railway)
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Add WhiteNoise for static files
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'phishield_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / "templates"],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.media',  # Added for media files
            ],
        },
    },
]

WSGI_APPLICATION = 'phishield_project.wsgi.application'

# ------------------------------
# Database
# ------------------------------
#DATABASES = {
    #'default': {
      #  'ENGINE': 'django.db.backends.sqlite3',
      #  'NAME': BASE_DIR / 'db.sqlite3',
    # }
#}

# ------------------------------
# Password Validation
# ------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# ------------------------------
# Internationalization
# ------------------------------
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Manila'
USE_I18N = True
USE_TZ = True

# ------------------------------
# Static & Media Files
# ------------------------------
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

# WhiteNoise configuration for static files
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# WhiteNoise configuration for media files (works on Railway, but files are ephemeral)
# For production, consider using cloud storage (AWS S3, Cloudinary) or Railway Volumes
WHITENOISE_USE_FINDERS = True  # Allow WhiteNoise to find media files

# File upload settings
FILE_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
DATA_UPLOAD_MAX_NUMBER_FIELDS = 1000   # Higher for complex forms

# ------------------------------
# Authentication
# ------------------------------
LOGIN_REDIRECT_URL = 'phishield:dashboard'
LOGOUT_REDIRECT_URL = 'phishield:login'
LOGIN_URL = 'phishield:login'

# Session settings
SESSION_COOKIE_AGE = 1209600  # 2 weeks in seconds
SESSION_SAVE_EVERY_REQUEST = True

# ------------------------------
# Email Configuration (UPDATED)
# ------------------------------
# REPLACED: Old Console Backend
# EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Email Configuration - Using SendGrid API (works on Railway)
# Railway blocks SMTP connections, so we use SendGrid's HTTP API instead
# Get your API key from: https://app.sendgrid.com/settings/api_keys

# Check if SendGrid API key is set, otherwise fall back to SMTP (for local dev)
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')

if SENDGRID_API_KEY:
    # Use SendGrid API via Anymail (works on Railway - uses HTTP, not SMTP)
    EMAIL_BACKEND = 'anymail.backends.sendgrid.EmailBackend'
    ANYMAIL = {
        "SENDGRID_API_KEY": SENDGRID_API_KEY,
    }
    DEFAULT_FROM_EMAIL = os.getenv('EMAIL_USER', 'phishield001@gmail.com')
else:
    # Fallback to SMTP for local development
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = 'smtp.gmail.com'
    email_port = int(os.getenv('EMAIL_PORT', '465'))
    EMAIL_PORT = email_port
    EMAIL_USE_SSL = (email_port == 465)
    EMAIL_USE_TLS = (email_port == 587)
    EMAIL_HOST_USER = os.getenv('EMAIL_USER')
    EMAIL_HOST_PASSWORD = os.getenv('EMAIL_PASSWORD')
    EMAIL_TIMEOUT = 10
    DEFAULT_FROM_EMAIL = os.getenv('EMAIL_USER', 'phishield001@gmail.com')

# Set the contact email
CONTACT_EMAIL = 'phishield001@gmail.com'

# Set the default sender to the authenticated email
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER or 'phishield001@gmail.com'
CONTACT_EMAIL = 'phishield001@gmail.com'

# For production (commented out for development)
"""
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.your-email-provider.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your-email@phishield.com'
EMAIL_HOST_PASSWORD = 'your-email-password'
"""

# ------------------------------
# Messages Framework
# ------------------------------
MESSAGE_TAGS = {
    messages.DEBUG: 'secondary',
    messages.INFO: 'info',
    messages.SUCCESS: 'success',
    messages.WARNING: 'warning',
    messages.ERROR: 'danger',
}

# ------------------------------
# Security Tips
# ------------------------------
SECURITY_TIPS = [
    "Always verify the sender's email address before clicking links.",
    "Check for HTTPS and a padlock icon in your browser's address bar.",
    "Be wary of urgent messages asking you to act immediately.",
    "Never share passwords or sensitive info via email or message.",
    "Hover over links to preview the actual URL before clicking.",
    "Be suspicious of shortened URLs from unknown sources.",
    "Look for spelling errors in domain names.",
    "Enable two-factor authentication on all important accounts.",
    "Keep your software and antivirus updated regularly.",
    "Use unique passwords for different online accounts.",
    "Regularly review your account activity and statements.",
    "Be cautious of attachments from unknown senders.",
    "Verify website security certificates before entering sensitive data.",
    "Use a password manager to generate and store strong passwords.",
    "Educate yourself about common phishing tactics and red flags.",
]

# ------------------------------
# Default Primary Key Field
# ------------------------------
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ------------------------------
# Custom Settings
# ------------------------------
EMAIL_VERIFICATION_EXPIRY_HOURS = 24
MAX_UPLOAD_SIZE = 5242880  # 5MB

# PhiShield Specific Settings
PHISHIELD_CONFIG = {
    'APP_NAME': 'PhiShield',
    'VERSION': '1.0.0',
    'SUPPORT_EMAIL': 'support@phishield.com',
    'MAX_URL_LENGTH': 500,
    'MAX_MESSAGE_LENGTH': 2000,
    'ANALYSIS_TIMEOUT': 30,  # seconds
    'ALLOWED_IMAGE_EXTENSIONS': ['jpg', 'jpeg', 'png', 'gif', 'webp'],
    'MAX_IMAGE_SIZE': 5242880,  # 5MB
}

# ------------------------------
# API Keys for Enhanced Phishing Detection
# ------------------------------
# Add these to your .env file:
# PHISHTANK_API_KEY=your_phishtank_api_key_here (optional - works without key but with rate limits)
# GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key_here (optional)
#
# To get API keys:
# - PhishTank: https://www.phishtank.com/api_register.php (free, optional)
# - Google Safe Browsing: https://console.cloud.google.com/apis/credentials (free tier available)
#
# Note: The system will work without these API keys, but with reduced detection accuracy.
# All other detection methods (typosquatting, domain reputation, etc.) work without API keys.

# ------------------------------
# Logging Configuration
# ------------------------------
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {asctime} {message}',
            'style': '{',
        },
        'detailed': {
            'format': '[{asctime}] {levelname} {name} - {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'phishield.log',
            'formatter': 'detailed',
            'encoding': 'utf-8',
        },
        'analysis_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'analysis.log',
            'formatter': 'detailed',
            'encoding': 'utf-8',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'error_file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'errors.log',
            'formatter': 'verbose',
            'encoding': 'utf-8',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['error_file', 'console'],
            'level': 'ERROR',
            'propagate': False,
        },
        'django.security': {
            'handlers': ['error_file'],
            'level': 'WARNING',
            'propagate': False,
        },
        'phishield': {
            'handlers': ['file', 'analysis_file', 'console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'phishield.analysis': {
            'handlers': ['analysis_file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
}

# ------------------------------
# Cache Configuration (Optional - for production)
# ------------------------------
"""
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379',
    }
}
"""

# ------------------------------
# Security Headers (for production)
# ------------------------------
"""
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
"""

# ------------------------------
# Custom Test Runner
# ------------------------------
TEST_RUNNER = 'django.test.runner.DiscoverRunner'

# ------------------------------
# Django Debug Toolbar (Development only)
# ------------------------------
# Uncomment after installing: pip install django-debug-toolbar
# if DEBUG:
#     INSTALLED_APPS += ['debug_toolbar']
#     MIDDLEWARE += ['debug_toolbar.middleware.DebugToolbarMiddleware']
#     INTERNAL_IPS = ['127.0.0.1']