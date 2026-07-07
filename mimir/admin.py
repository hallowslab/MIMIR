from django.contrib import admin
from .models import TargetServer, MimirJob, SecurityAlert

admin.site.register(TargetServer)
admin.site.register(MimirJob)
admin.site.register(SecurityAlert)
