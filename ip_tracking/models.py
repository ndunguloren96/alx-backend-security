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
    country = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name="Country"
    )
    city = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name="City"
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
    Model to store IP addresses that have been blocked.
    """
    ip_address = models.GenericIPAddressField(
        verbose_name="Blocked IP Address",
        unique=True,
        help_text="The IP address that has been blocked."
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Timestamp",
        help_text="The time the IP was blocked."
    )
    reason = models.TextField(
        blank=True,
        verbose_name="Reason for Block",
        help_text="The reason why this IP address was blocked."
    )

    def __str__(self):
        """
        Human-readable representation of the blocked IP.
        """
        return f"Blocked: {self.ip_address}"

    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ['-timestamp']


class SuspiciousIP(models.Model):
    """
    Model to store IP addresses that have been flagged as suspicious.
    """
    ip_address = models.GenericIPAddressField(
        unique=True,
        verbose_name="Suspicious IP Address",
        help_text="An IP address flagged for unusual behavior."
    )
    reason = models.TextField(
        verbose_name="Reason for Flag",
        help_text="The specific unusual behavior detected."
    )
    first_detected_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="First Detected At",
        help_text="The first time this IP was flagged."
    )
    last_detected_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Last Detected At",
        help_text="The most recent time this IP was flagged."
    )

    def __str__(self):
        return f"Suspicious IP: {self.ip_address}"

    def save(self, *args, **kwargs):
        """Update last_detected_at on save."""
        self.last_detected_at = timezone.now()
        super().save(*args, **kwargs)

    class Meta:
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        ordering = ['-last_detected_at']
