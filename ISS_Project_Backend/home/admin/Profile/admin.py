from django.contrib import admin
from ...models import *

class ProfileAdmin(admin.ModelAdmin):
    model = Profile
    list_display = ('user', 'first_name', 'last_name', 'birth_date', 'gender')
    search_fields = ('user__username', 'first_name', 'last_name')
    list_filter = ('gender',)
    fieldsets = (
        ('User Info', {'fields': ('user',)}),
        ('Profile Details', {'fields': ('first_name', 'last_name', 'birth_date', 'gender')}),
    )

admin.site.register(Profile, ProfileAdmin)  # Properly registering the model and admin class
