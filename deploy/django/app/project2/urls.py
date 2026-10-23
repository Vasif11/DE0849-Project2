from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),  # /accounts/login/, /accounts/logout/
    path("", include("core.urls")),
]
