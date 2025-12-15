"""
Dark Knight Phantom SIEM - Detection Admin
"""
from django.contrib import admin
from .models import DetectionRule, DetectionAlert, EntityTracker, AlertSuppressionRule


@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'severity', 'category', 'rule_type', 'enabled', 'total_alerts', 'false_positive_rate']
    list_filter = ['severity', 'category', 'rule_type', 'enabled', 'is_builtin']
    search_fields = ['name', 'description', 'mitre_technique']
    readonly_fields = ['id', 'created_at', 'updated_at', 'total_alerts', 'false_positives']


@admin.register(DetectionAlert)
class DetectionAlertAdmin(admin.ModelAdmin):
    list_display = ['title', 'severity', 'status', 'hostname', 'user_name', 'triggered_at', 'confidence']
    list_filter = ['severity', 'status', 'rule__category']
    search_fields = ['title', 'hostname', 'user_name', 'source_ip']
    readonly_fields = ['id', 'triggered_at']
    date_hierarchy = 'triggered_at'


@admin.register(EntityTracker)
class EntityTrackerAdmin(admin.ModelAdmin):
    list_display = ['entity_type', 'entity_value', 'hostname', 'window_start', 'last_event_time']
    list_filter = ['entity_type']
    search_fields = ['entity_value', 'hostname']


@admin.register(AlertSuppressionRule)
class AlertSuppressionRuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'detection_rule', 'enabled', 'expires_at', 'created_at']
    list_filter = ['enabled', 'detection_rule']
    search_fields = ['name', 'reason']



