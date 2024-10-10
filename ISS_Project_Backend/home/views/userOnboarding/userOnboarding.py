from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from ...forms.userOnboarding.userOnboarding import UserOnboardingForm
from ...models import *
from django.contrib import messages

@login_required
def user_onboarding(request):
    profile = request.user.profile  # Access the profile associated with the logged-in user
    if request.method == 'POST':
        form = UserOnboardingForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile information updated successfully.')
            return redirect('home')  # Redirect to home after onboarding
    else:
        form = UserOnboardingForm(instance=profile)
    
    return render(request, 'userOnboarding/user_onboarding.html', {'form': form})
