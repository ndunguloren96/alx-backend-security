# alx-backend-security/ip_tracking/models.py

from django.db import models

class RequestLog(models.Model):
    """
    Model to log basic details of every incoming request.
    """
    ip_address = models.GenericIPAddressField(
        verbose_name="IP Address",
        help_text="The IP address of the client making the request."
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Timestamp",
        help_text="The time the request was received."
    )
    path = models.CharField(
        max_length=255,
        verbose_name="Path",
        help_text="The requested URL path."
    )

    def __str__(self):
        """
        Human-readable representation of the log entry.
        """
        return f"{self.ip_address} requested {self.path} at {self.timestamp}"

    class Meta:
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        ordering = ['-timestamp']
