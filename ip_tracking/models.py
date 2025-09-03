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


class BlockedIP(models.Model):
    """
    Model to store IP addresses that are blocked from accessing the site.
    """
    ip_address = models.GenericIPAddressField(
        unique=True,
        verbose_name="Blocked IP Address",
        help_text="An IP address that is explicitly blocked."
    )
    reason = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name="Reason for Block",
        help_text="Reason for blocking this IP, e.g., 'spam bot', 'brute force attack'."
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Blocked At",
        help_text="The timestamp when this IP was added to the blacklist."
    )

    def __str__(self):
        return f"Blocked IP: {self.ip_address}"

    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ['-created_at']
