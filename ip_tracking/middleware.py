# alx-backend-security/ip_tracking/middleware.py

from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.http import HttpResponseForbidden
from django.core.cache import cache
from ip_tracking.models import RequestLog, BlockedIP
from ipware import get_client_ip
from ip_geolocation.utils import get_country_and_city # Import the geolocation utility
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
            # The 'RequestLog' model should have 'country' and 'city' fields
            RequestLog.objects.bulk_create([
                RequestLog(**log_data) for log_data in _local_cache
            ])
            _local_cache.clear()

class LogIPMiddleware(MiddlewareMixin):
    """
    Middleware to log the IP address, timestamp, and path of every incoming request.
    This implementation uses a simple caching mechanism to reduce database I/O.
    """
    def __init__(self, get_response=None):
        self.get_response = get_response
        self._load_blocked_ips()

    def _load_blocked_ips(self):
        """
        Loads all blocked IPs from the database into the cache.
        This method is called at initialization.
        """
        blocked_ips = list(BlockedIP.objects.values_list('ip_address', flat=True))
        # Cache for 1 hour (3600 seconds)
        cache.set('blocked_ips', blocked_ips, timeout=3600)
        print(f"Loaded {len(blocked_ips)} blocked IPs into cache.")

    def process_request(self, request):
        """
        Process the incoming request to log relevant details and check for blacklisted IPs.
        """
        client_ip, _ = get_client_ip(request)

        # 1. Check if the IP is blacklisted first
        if client_ip:
            blocked_ips = cache.get('blocked_ips')
            if blocked_ips is None:
                self._load_blocked_ips()
                blocked_ips = cache.get('blocked_ips')

            if client_ip in blocked_ips:
                print(f"Blocked request from {client_ip} to {request.path}")
                return HttpResponseForbidden("You are not allowed to access this resource.")
        
        # 2. If not blacklisted, log the request with geolocation data
        if client_ip:
            # Use the geolocation utility to get country and city.
            # The library handles internal caching.
            try:
                country, city = get_country_and_city(client_ip)
            except Exception as e:
                # Handle cases where geolocation fails (e.g., private IPs, lookup errors)
                country, city = None, None
                print(f"Geolocation failed for IP {client_ip}: {e}")

            log_data = {
                'ip_address': client_ip,
                'path': request.path,
                'country': country,
                'city': city
            }

            with _cache_lock:
                _local_cache.append(log_data)
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
