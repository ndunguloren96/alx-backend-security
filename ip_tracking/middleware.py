# alx-backend-security/ip_tracking/middleware.py

from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from ip_tracking.models import RequestLog
from ipware import get_client_ip
import threading

# A local cache for IPs to avoid excessive database writes on very high traffic.
# The cache will be flushed periodically or based on a specific strategy.
# Using a lock for thread-safe access.
_local_cache = []
_cache_lock = threading.Lock()
_cache_limit = getattr(settings, 'REQUEST_LOG_CACHE_LIMIT', 50) # default to 50 logs per batch

def save_logs_from_cache():
    """
    Saves logs from the local cache to the database in a separate thread.
    This helps to avoid blocking the main request-response cycle.
    """
    with _cache_lock:
        if _local_cache:
            RequestLog.objects.bulk_create([
                RequestLog(**log_data) for log_data in _local_cache
            ])
            _local_cache.clear()

class LogIPMiddleware(MiddlewareMixin):
    """
    Middleware to log and block IP addresses.
    """
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.get_response = get_response
        self._load_blocked_ips()

    def _load_blocked_ips(self):
        """Loads blocked IPs into cache to reduce DB queries."""
        # Using a simple cache. Consider using Redis for production.
        blocked_ips = list(BlockedIP.objects.values_list('ip_address', flat=True))
        cache.set('blocked_ips', blocked_ips, timeout=60 * 60) # Cache for 1 hour

    def process_request(self, request):
        client_ip, _ = get_client_ip(request)

        # 1. Check if the IP is blacklisted first
        if client_ip:
            blocked_ips = cache.get('blocked_ips')
            if blocked_ips is None:
                self._load_blocked_ips()
                blocked_ips = cache.get('blocked_ips')

            if client_ip in blocked_ips:
                # Log the attempted access of the blocked IP
                print(f"Blocked request from {client_ip} to {request.path}")
                # Return 403 Forbidden response
                return HttpResponseForbidden("You are not allowed to access this resource.")
        
        # 2. If not blacklisted, log the request
        if client_ip:
            log_data = {
                'ip_address': client_ip,
                'path': request.path,
            }

            with _cache_lock:
                _local_cache.append(log_data)
                if len(_local_cache) >= _cache_limit:
                    threading.Thread(target=save_logs_from_cache).start()
        
        return None
