#!/bin/sh
# Initialise the database, ensure the controlled lab account exists, then serve with Gunicorn.
set -e

echo "[django] manage.py check"
python manage.py check

echo "[django] creating/applying migrations"
python manage.py makemigrations core --noinput
python manage.py migrate --noinput

echo "[django] ensuring lab account '${LAB_USER:-securityadmin}' exists"
python manage.py shell <<'PY'
import os
from django.contrib.auth import get_user_model
U = get_user_model()
name = os.environ.get("LAB_USER", "securityadmin")
pw = os.environ.get("LAB_PASSWORD", "SecureLab!2026")
u, created = U.objects.get_or_create(username=name, defaults={"is_staff": True, "is_superuser": True})
u.is_staff = True
u.is_superuser = True
u.set_password(pw)
u.save()
print("[django] account", name, "created" if created else "updated")
PY

echo "[django] starting gunicorn on 0.0.0.0:8000"
exec gunicorn project2.wsgi:application \
  --bind 0.0.0.0:8000 --workers 2 --threads 2 --timeout 60 --access-logfile - --error-logfile -
