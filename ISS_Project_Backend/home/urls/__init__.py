from django.urls import include, path

urlpatterns = [
    path('', include('home.urls.authentication.authentication')), 
    path('', include('home.urls.userOnboarding.userOnboarding')), 
]
