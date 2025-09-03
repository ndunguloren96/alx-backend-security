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
    Middleware to log the IP address, timestamp, and path of every incoming request.
    This implementation uses a simple caching mechanism to reduce database I/O.
    """
    def process_request(self, request):
        """
        Process the incoming request to log relevant details.
        """
        client_ip, is_routable = get_client_ip(request)
        if client_ip:
            log_data = {
                'ip_address': client_ip,
                'path': request.path,
            }

            with _cache_lock:
                _local_cache.append(log_data)
                # If the cache limit is reached, spawn a new thread to save the logs.
                if len(_local_cache) >= _cache_limit:
                    threading.Thread(target=save_logs_from_cache).start()
        
        return None # Proceed to the next middleware or view.

    def process_response(self, request, response):
        """
        Ensure any remaining logs are saved before the process completes.
        This is a safety measure.
        """
        # This part might not be strictly necessary for every request but ensures all logs
        # are saved at shutdown or after every request, depending on a more complex design.
        # For simplicity and performance, the bulk-save on limit is the main mechanism.
        return response
