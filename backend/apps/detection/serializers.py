"""
Dark Knight Phantom SIEM - Detection Serializers
"""
from rest_framework import serializers
from .models import DetectionRule, DetectionAlert, EntityTracker, AlertSuppressionRule


class DetectionRuleSerializer(serializers.ModelSerializer):
    false_positive_rate = serializers.ReadOnlyField()
    
    class Meta:
        model = DetectionRule
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at', 'total_alerts', 'false_positives']


class DetectionRuleListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views"""
    false_positive_rate = serializers.ReadOnlyField()
    
    class Meta:
        model = DetectionRule
        fields = [
            'id', 'name', 'description', 'severity', 'rule_type', 'category',
            'enabled', 'is_builtin', 'total_alerts', 'false_positives', 
            'false_positive_rate', 'mitre_technique'
        ]


class DetectionAlertSerializer(serializers.ModelSerializer):
    """Full alert serializer with complete event evidence"""
    rule_name = serializers.CharField(source='rule.name', read_only=True)
    rule_category = serializers.CharField(source='rule.category', read_only=True)
    rule_logic = serializers.JSONField(source='rule.logic', read_only=True)
    matched_events_data = serializers.SerializerMethodField()
    
    class Meta:
        model = DetectionAlert
        fields = '__all__'
        read_only_fields = ['id', 'triggered_at', 'rule']
    
    def get_matched_events_data(self, obj):
        """Get full event data for all matched events - shows WHY alert was triggered"""
        from apps.events.models import SecurityEvent
        
        if not obj.matched_events:
            return []
        
        events = SecurityEvent.objects.filter(id__in=obj.matched_events).order_by('timestamp')
        return [
            {
                'id': e.id,
                'event_id': e.event_id,
                'timestamp': e.timestamp.isoformat(),
                'hostname': e.hostname,
                'channel': e.channel,
                'message': e.message,
                'user_name': e.user_name,
                'target_user_name': e.target_user_name,
                'source_ip': str(e.source_ip) if e.source_ip else None,
                'process_name': e.process_name,
                'command_line': e.command_line,
                'logon_type': e.logon_type,
                'logon_type_name': e.logon_type_name,
                'service_name': e.service_name,
                'status': e.status,
                'failure_reason': e.failure_reason,
                'raw_xml': e.raw_xml[:2000] if e.raw_xml else '',  # First 2000 chars
                'event_data': e.event_data,
            }
            for e in events[:50]  # Limit to 50 events
        ]


class DetectionAlertListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views"""
    rule_name = serializers.CharField(source='rule.name', read_only=True)
    rule_category = serializers.CharField(source='rule.category', read_only=True)
    rule_logic = serializers.JSONField(source='rule.logic', read_only=True)
    rule = serializers.SerializerMethodField()
    
    class Meta:
        model = DetectionAlert
        fields = [
            'id', 'title', 'description', 'severity', 'status', 'hostname', 'user_name',
            'source_ip', 'confidence', 'triggered_at', 'rule_name', 
            'rule_category', 'rule_logic', 'event_count', 'matched_events', 'evidence',
            'first_event_time', 'last_event_time', 'rule'
        ]
    
    def get_rule(self, obj):
        """Include minimal rule info"""
        if obj.rule:
            return {
                'id': str(obj.rule.id),
                'name': obj.rule.name,
                'category': obj.rule.category,
                'mitre_tactic': obj.rule.mitre_tactic or '',
                'mitre_technique': obj.rule.mitre_technique or '',
            }
        return None


class AlertUpdateSerializer(serializers.Serializer):
    """Serializer for updating alert status"""
    status = serializers.ChoiceField(choices=DetectionAlert.STATUS_CHOICES)
    notes = serializers.CharField(required=False, allow_blank=True)
    assigned_to = serializers.CharField(required=False, allow_blank=True)
    resolution_notes = serializers.CharField(required=False, allow_blank=True)


class EntityTrackerSerializer(serializers.ModelSerializer):
    total_events = serializers.SerializerMethodField()
    
    class Meta:
        model = EntityTracker
        fields = '__all__'
    
    def get_total_events(self, obj):
        return obj.get_total_count()


class AlertSuppressionRuleSerializer(serializers.ModelSerializer):
    is_active = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = AlertSuppressionRule
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class AlertStatsSerializer(serializers.Serializer):
    """Serializer for alert statistics"""
    total = serializers.IntegerField()
    new = serializers.IntegerField()
    investigating = serializers.IntegerField()
    resolved = serializers.IntegerField()
    false_positive = serializers.IntegerField()
    by_severity = serializers.DictField()
    by_category = serializers.ListField()
    recent_24h = serializers.IntegerField()

