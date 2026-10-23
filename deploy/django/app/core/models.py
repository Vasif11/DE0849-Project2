from django.conf import settings
from django.db import models


class Feedback(models.Model):
    """Message submitted through the authenticated, CSRF-protected /feedback/ form."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} @ {self.created_at:%Y-%m-%d %H:%M}"
