from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone

from .models import Feedback


# ---- public resources ----------------------------------------------------
def home(request):
    return render(request, "home.html")


def health(request):
    # Docker/Nginx health probe target.
    return JsonResponse(
        {"service": "project2-django", "status": "ok", "project": "Telecommunication Security"}
    )


def api_status(request):
    return JsonResponse(
        {
            "status": "operational",
            "service": "project2-django",
            "time": timezone.now().isoformat(),
            "authenticated": request.user.is_authenticated,
        }
    )


def search(request):
    # Public search. The query is handled safely: the Django template auto-escapes it, and the
    # ORM (if used) parametrises queries, so reflected input cannot inject HTML or SQL.
    query = request.GET.get("q", "")
    results = []
    if query:
        catalogue = [
            "5G user-plane overview",
            "N6 data network",
            "TLS gateway configuration",
            "Authentication and access control",
            "CSRF protection",
            "Security headers and HSTS",
        ]
        results = [item for item in catalogue if query.lower() in item.lower()]
    return render(request, "search.html", {"query": query, "results": results})


# ---- protected resources -------------------------------------------------
@login_required
def profile(request):
    return render(request, "profile.html")


@login_required
def feedback(request):
    # Authenticated, CSRF-protected form. A POST without a valid CSRF token is rejected with 403
    # by Django's CsrfViewMiddleware (the control is NOT disabled to make the test pass).
    saved = False
    if request.method == "POST":
        message = request.POST.get("message", "").strip()
        if message:
            Feedback.objects.create(user=request.user, message=message)
            saved = True
    recent = Feedback.objects.filter(user=request.user).order_by("-created_at")[:5]
    return render(request, "feedback.html", {"saved": saved, "recent": recent})
