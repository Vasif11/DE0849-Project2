"""Django settings for the Scenario A secure application baseline.

Security-relevant settings are driven by the Phase 1D requirements of the guidebook:
secure cookies, HSTS, proxy SSL header, and Django's security middleware (X-Frame-Options,
X-Content-Type-Options, Referrer-Policy).
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _bool(name, default="False"):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def _list(name, default=""):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


# --- core -----------------------------------------------------------------
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-insecure-change-me")
DEBUG = _bool("DJANGO_DEBUG", "False")
ALLOWED_HOSTS = _list(
    "DJANGO_ALLOWED_HOSTS",
    "10.20.8.20,10.20.6.20,telecom-lab.local,localhost,127.0.0.1",
)
# POST over HTTPS (TLS terminated at Nginx) needs trusted origins in Django 4+.
CSRF_TRUSTED_ORIGINS = _list(
    "DJANGO_CSRF_TRUSTED_ORIGINS",
    "https://10.20.6.20,https://telecom-lab.local,https://localhost",
)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",     # HSTS, nosniff, SSL header
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",          # CSRF protection (kept enabled)
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",  # X-Frame-Options
]

ROOT_URLCONF = "project2.urls"
WSGI_APPLICATION = "project2.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("DJANGO_DB_PATH", "/app/data/db.sqlite3"),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/profile/"
LOGOUT_REDIRECT_URL = "/"

# --- Phase 1D security baseline ------------------------------------------
# TLS terminates at Nginx; Django recognises the original request as HTTPS via this header.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Authentication / CSRF cookies only over HTTPS.
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

# HSTS short-duration laboratory baseline.
SECURE_HSTS_SECONDS = 3600
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

# Security headers.
SECURE_CONTENT_TYPE_NOSNIFF = True         # X-Content-Type-Options: nosniff
SECURE_REFERRER_POLICY = "same-origin"     # Referrer-Policy: same-origin
X_FRAME_OPTIONS = "DENY"                    # X-Frame-Options: DENY

# Nginx performs the HTTP->HTTPS redirect; Django must not double-redirect behind the proxy.
SECURE_SSL_REDIRECT = False
