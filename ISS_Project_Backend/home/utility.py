import logging
import socket
from urllib.parse import urlparse
import requests
from django.utils.timezone import now

logger = logging.getLogger('outgoing_requests')

def log_outgoing_request(url, user=None):
    try:
        # Parse URL to extract hostname
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        ip = socket.gethostbyname(host)
        
        # Log details of the request
        logger.info({
            "timestamp": now().isoformat(),
            "user": user.username if user else "anonymous",
            "url": url,
            "resolved_ip": ip,
        })
    except Exception as e:
        logger.error(f"Error logging outgoing request: {e}")

def safe_http_request(url, user=None):
    # Log the outgoing request
    log_outgoing_request(url, user)

    try:
        # Make the actual HTTP request
        response = requests.get(url, timeout=5)
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP request failed: {e}")
        return None
