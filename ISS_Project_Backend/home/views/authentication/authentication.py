from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from ...models import Profile
import requests
from urllib.parse import urlparse

# Allowed domains for any outbound HTTP requests 
ALLOWED_DOMAINS = ['127.0.0.1', 'localhost']


# Helper function to prevent SSRF by whitelisting URLs
def is_safe_url(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        return domain in ALLOWED_DOMAINS
    except ValueError:
        return False

def safe_http_request(url):
    if is_safe_url(url):
        try:
            response = requests.get(url, timeout=5)
            return response
        except requests.exceptions.RequestException:
            return None
    else:
        raise ValueError("Blocked request to non-allowed URL.")

# Modified login view with a simulated safe HTTP request for external profile verification
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Example of fetching user profile info from an external service (simulated)
            external_profile_url = request.POST.get('external_profile_url', '')
            if external_profile_url:
                try:
                    # Validate and fetch external profile data
                    external_response = safe_http_request(external_profile_url)
                    if external_response:
                        # Do something with external profile data (optional)
                        print("Fetched external profile data:", external_response.json())
                    else:
                        messages.warning(request, 'Failed to fetch external profile.')
                except ValueError:
                    messages.error(request, 'Blocked request to non-allowed URL.')

            login(request, user)
            return redirect('user_onboarding')
        else:
            messages.error(request, 'Invalid username or password.')
    
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
