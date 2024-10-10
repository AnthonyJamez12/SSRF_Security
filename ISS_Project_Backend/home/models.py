from django.db import models
from django.contrib.auth.models import User




class Profile(models.Model):
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
    ]
    


    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.TextField(max_length=150, blank=True)
    last_name = models.TextField(max_length=150, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, blank=True)


    def __str__(self):
        return f'{self.user.username} Profile'

