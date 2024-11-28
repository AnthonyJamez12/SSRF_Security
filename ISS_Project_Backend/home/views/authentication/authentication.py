from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from ...models import Profile
import requests
from urllib.parse import urlparse
import json
from django.http import JsonResponse
from urllib.parse import unquote
import ipaddress
import socket
import logging
from django.utils.timezone import now  # Import Django's timezone-aware 'now' function
import time

# Rate-limiting storage (global dictionary)
RATE_LIMITING = {}
RATE_LIMIT = 10  # Maximum number of requests
TIME_WINDOW = 60  # Time window in seconds
ALLOWED_DOMAINS = ['127.0.0.1', 'localhost'] # Allowed domains for any outbound HTTP requests 

logger = logging.getLogger('outgoing_requests')


def validate_dns_rebinding(url):
    try:
        hostname = urlparse(url).hostname
        resolved_ips = {socket.gethostbyname(hostname) for _ in range(3)}  # Resolve 3 times
        if len(resolved_ips) > 1:  # IPs differ across resolutions
            raise ValueError("Potential DNS rebinding detected.")
    except Exception as e:
        logger.error(f"DNS validation failed: {e}")
        return JsonResponse({"error": "Failed DNS validation."}, status=400)


def is_rate_limited(user_identifier):
    current_time = time.time()
    user_data = RATE_LIMITING.get(user_identifier, {"count": 0, "start_time": current_time})

    # Calculate elapsed time since the first request in the current window
    elapsed_time = current_time - user_data["start_time"]

    if elapsed_time > TIME_WINDOW:
        # Reset rate limiting if the time window has expired
        RATE_LIMITING[user_identifier] = {"count": 1, "start_time": current_time}
        return False

    if user_data["count"] >= RATE_LIMIT:
        # User is rate-limited
        return True

    # Increment the request count within the current window
    user_data["count"] += 1
    RATE_LIMITING[user_identifier] = user_data
    return False


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

# Helper function to check if an IP is in restricted ranges
def is_restricted_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_private or         # Private IPs
            ip_obj.is_loopback or        # Loopback (127.0.0.1)
            ip_obj.is_reserved or        # Reserved ranges
            ip.startswith('169.254')     # Cloud metadata service (AWS, GCP, etc.)
        )
    except ValueError:
        return True  # Treat invalid IPs as restricted

def is_safe_url(url):
    try:
        # Parse the URL to get components
        parsed_url = urlparse(url)
        
        # Ensure the URL has a valid scheme (http or https)
        if parsed_url.scheme not in ['http', 'https']:
            return JsonResponse({"error": "Invalid URL scheme. Only http and https are allowed."}, status=400)
        
        # Extract the domain (hostname) from the URL and check if it's allowed
        domain = parsed_url.hostname
        if domain not in ALLOWED_DOMAINS:
            print("Domain not allowed.")
            return JsonResponse({"error": "Domain not allowed."}, status=403)
        
        # Decode the URL-encoded query string before checking for suspicious characters
        decoded_url = unquote(url)

        # Check for suspicious characters in the full decoded URL
        if any(c in decoded_url for c in ['<', '>', '"', '\'', ';', '--']):
            return JsonResponse({"error": "Suspicious characters detected in the URL."}, status=400)

        # Optional: Validate query parameters separately if needed
        query_string = parsed_url.query  # This retrieves the query string part of the URL
        decoded_query_string = unquote(query_string)  # Decode the query string
        if any(c in decoded_query_string for c in ['<', '>', '"', '\'', ';', '--']):
            return JsonResponse({"error": "Suspicious characters detected in the query string."}, status=400)
        
        # Perform DNS rebinding validation
        validate_dns_rebinding(url)


        domain = parsed_url.hostname
        ip = socket.gethostbyname(domain)

        # Block restricted IP ranges
        if domain not in ALLOWED_DOMAINS:
            return JsonResponse({"error": "Domain not allowed."}, status=403)

        # Make an HTTP request to the URL with a timeout
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)  # Set timeout
            if response.status_code in [301, 302, 303, 307, 308]:  # Handle redirect status codes
                return JsonResponse({"error": "Redirects are not allowed."}, status=400)
            return response
        except requests.exceptions.Timeout:
            return JsonResponse({"error": "Request timed out."}, status=408)
        except requests.exceptions.RequestException as e:
            return JsonResponse({"error": f"Request failed: {str(e)}"}, status=500)

    except (ValueError, TypeError) as e:
        # Return a JSON error response with the specific validation failure
        return JsonResponse({"error": f"URL validation failed: {str(e)}"}, status=400)



def safe_http_request(url, user=None):
    # Use username or IP as a unique identifier for rate limiting
    user_identifier = user.username if user else "anonymous"

    # Check rate limit
    if is_rate_limited(user_identifier):
        return JsonResponse({"error": "Rate limit exceeded. Please try again later."}, status=429)
    
    # Call is_safe_url to validate the URL
    log_outgoing_request(url, user)

    is_safe = is_safe_url(url)
    
    # If is_safe_url returns a JsonResponse (indicating an error), return it directly
    if isinstance(is_safe, JsonResponse):
        return is_safe  # Return the JSON response with the error message
    
     # Make the HTTP request with redirects disabled
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)  # Disable redirects
        if response.status_code in [301, 302, 303, 307, 308]:  # Handle redirect status codes
            return JsonResponse({"error": "Redirects are not allowed."}, status=400)
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP request failed: {e}")
        return JsonResponse({"error": "Failed to make the HTTP request."}, status=500)
    


# Updated login view with external profile URL validation and HTTP request
def login_view(request):
    # Build the full request URL (this includes the query parameters)
    full_request_url = request.build_absolute_uri()  # This gives the complete URL including query params
    
    # Validate the full request URL (including query parameters) using is_safe_url
    is_safe = is_safe_url(full_request_url)  # Pass the full request URL to is_safe_url
    if isinstance(is_safe, JsonResponse):
        return is_safe  # If is_safe_url returns a JsonResponse, return it as the response
    
    if request.method == 'POST':
        try:
            # Parse the incoming JSON data
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')
            external_profile_url = data.get('external_profile_url')  # External URL to validate
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
        # Ensure username and password are provided
        if not username or not password:
            return JsonResponse({'error': 'Username or password not provided'}, status=400)

        # Validate the external profile URL if provided
        if external_profile_url:
            external_response = safe_http_request(external_profile_url)
            
            # If safe_http_request returns a JsonResponse, it means the URL validation failed
            if isinstance(external_response, JsonResponse):
                return external_response
            
            if external_response:
                print("Fetched external profile data.")  # Debugging success
            else:
                print("Failed to fetch external profile.")  # Debugging failure
                return JsonResponse({'warning': 'Failed to fetch external profile.'}, status=400)
        
        # Authenticate user
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({'message': 'Login successful'}, status=200)
        else:
            print(f"User {username} failed to authenticate.")  # Debugging failed login
            return JsonResponse({'error': 'Invalid username or password'}, status=401)
    
    return render(request, 'authentication/login.html')




def logout_view(request):
    logout(request)
    return redirect('login')  

def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            Profile.objects.create(user=user)  # Create the associated profile
            # Automatically log the user in after registration
            login(request, user)  
            messages.success(request, 'Account created successfully.')
            return redirect('user_onboarding')
    else:
        form = UserCreationForm()
    
    return render(request, 'authentication/register.html', {'form': form})
