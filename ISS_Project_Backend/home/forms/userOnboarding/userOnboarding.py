from django import forms
from ...models import *

GENDER_CHOICES = [
    ('M', 'Male'),
    ('F', 'Female'),
]

class UserOnboardingForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['first_name', 'last_name', 'birth_date', 'gender']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'First Name'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Last Name'}),
            'birth_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'gender': forms.Select(choices=GENDER_CHOICES, attrs={'class': 'form-control'}),  # Gender dropdown
        }

