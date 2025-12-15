from django.contrib import admin
from .models import Alert, AlertComment

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['alert_id', 'title', 'severity', 'status', 'hostname', 'created_at']
    list_filter = ['severity', 'status']
    search_fields = ['title', 'description', 'hostname', 'rule_name']
    date_hierarchy = 'created_at'
    readonly_fields = ['id', 'alert_id', 'created_at', 'updated_at']

@admin.register(AlertComment)
class AlertCommentAdmin(admin.ModelAdmin):
    list_display = ['alert', 'author', 'created_at']
    list_filter = ['author']



