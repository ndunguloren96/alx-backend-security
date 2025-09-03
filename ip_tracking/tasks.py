# alx-backend-security/ip_tracking/tasks.py

from celery import shared_task
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta
from ip_tracking.models import RequestLog, SuspiciousIP

@shared_task
def detect_anomalies():
    """
    Celery task to detect and flag suspicious IPs based on log data.
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)
    
    # 1. Flag IPs with excessive requests in the last hour
    excessive_traffic_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).values('ip_address').annotate(
        request_count=Count('ip_address')
    ).filter(
        request_count__gte=100
    )

    for item in excessive_traffic_ips:
        ip = item['ip_address']
        SuspiciousIP.objects.update_or_create(
            ip_address=ip,
            defaults={'reason': f"Exceeded request limit: {item['request_count']} requests in the last hour."}
        )

    # 2. Flag IPs accessing sensitive paths
    sensitive_paths = ['/admin', '/login']
    suspicious_path_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago,
        path__in=sensitive_paths
    ).values('ip_address').distinct()

    for item in suspicious_path_ips:
        ip = item['ip_address']
        SuspiciousIP.objects.update_or_create(
            ip_address=ip,
            defaults={'reason': f"Accessed sensitive paths ({', '.join(sensitive_paths)}) in the last hour."}
        )
    
    # You might want to combine the logic to avoid multiple DB writes for the same IP
    # and provide a more comprehensive reason.
    # The current approach is simple and clear.
