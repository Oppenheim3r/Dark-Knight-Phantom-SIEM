"""
Dark Knight Phantom SIEM - Alert Serializers
"""
from rest_framework import serializers
from .models import Alert, AlertComment


class AlertCommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertComment
        fields = '__all__'
        read_only_fields = ['created_at']


class AlertSerializer(serializers.ModelSerializer):
    comments = AlertCommentSerializer(many=True, read_only=True)
    
    class Meta:
        model = Alert
        fields = '__all__'
        read_only_fields = ['id', 'alert_id', 'created_at', 'updated_at']


class AlertListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views"""
    comment_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Alert
        fields = [
            'id', 'alert_id', 'title', 'severity', 'status',
            'hostname', 'user_name', 'event_count', 'rule_name',
            'created_at', 'first_seen', 'last_seen', 'assigned_to',
            'comment_count'
        ]
    
    def get_comment_count(self, obj):
        return obj.comments.count()


class AlertCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'
        read_only_fields = ['id', 'alert_id', 'created_at', 'updated_at']



