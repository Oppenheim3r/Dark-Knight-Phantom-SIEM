from django.contrib import admin
from .models import SecurityEvent, EventSource, EventCategory, EventStatistics

@admin.register(EventSource)
class EventSourceAdmin(admin.ModelAdmin):
    list_display = ['name', 'provider', 'is_active', 'created_at']
    list_filter = ['is_active']
    search_fields = ['name', 'provider']

@admin.register(EventCategory)
class EventCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'description']

@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ['event_id', 'hostname', 'timestamp', 'severity', 'channel', 'user_name']
    list_filter = ['severity', 'channel', 'hostname']
    search_fields = ['hostname', 'user_name', 'message', 'command_line']
    date_hierarchy = 'timestamp'
    readonly_fields = ['received_at']

@admin.register(EventStatistics)
class EventStatisticsAdmin(admin.ModelAdmin):
    list_display = ['hour', 'hostname', 'channel', 'event_id', 'count']
    list_filter = ['hostname', 'channel']
    date_hierarchy = 'hour'



