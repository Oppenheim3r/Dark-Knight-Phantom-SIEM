"""
Dark Knight Phantom SIEM - Event Serializers
"""
from rest_framework import serializers
from .models import SecurityEvent, EventSource, EventCategory, RawEventBatch


class EventSourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventSource
        fields = '__all__'


class EventCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = EventCategory
        fields = '__all__'


class SecurityEventSerializer(serializers.ModelSerializer):
    """Full event serializer with all details"""
    source_name = serializers.CharField(source='source.name', read_only=True)
    category_name = serializers.CharField(source='category.name', read_only=True)
    
    class Meta:
        model = SecurityEvent
        fields = '__all__'


class SecurityEventListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views - shows RAW log data"""
    source_name = serializers.CharField(source='source.name', read_only=True)
    
    class Meta:
        model = SecurityEvent
        fields = [
            'id', 'event_id', 'timestamp', 'hostname', 'channel',
            'level', 'level_name', 'message', 'user_name', 
            'target_user_name', 'source_ip', 'process_name', 'process_path',
            'command_line', 'source_name', 'agent_id', 'provider_name', 
            'task_name', 'logon_type', 'logon_type_name'
        ]


class SecurityEventCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating events (from agents)"""
    
    class Meta:
        model = SecurityEvent
        fields = '__all__'
    
    def create(self, validated_data):
        # Auto-categorize based on event_id and channel
        event = SecurityEvent.objects.create(**validated_data)
        return event


class BulkEventSerializer(serializers.Serializer):
    """Serializer for bulk event ingestion"""
    events = SecurityEventCreateSerializer(many=True)
    agent_id = serializers.CharField(max_length=100)
    batch_id = serializers.CharField(max_length=100, required=False)
    
    def create(self, validated_data):
        events_data = validated_data.pop('events')
        agent_id = validated_data.get('agent_id')
        
        events = []
        for event_data in events_data:
            event_data['agent_id'] = agent_id
            events.append(SecurityEvent(**event_data))
        
        # Bulk create for performance
        created_events = SecurityEvent.objects.bulk_create(events, batch_size=1000)
        return {'count': len(created_events), 'events': created_events}


class EventIngestSerializer(serializers.Serializer):
    """
    Simplified serializer for agent event submission
    Accepts the raw event data from Windows Event Log
    """
    # Required fields
    event_id = serializers.IntegerField()
    timestamp = serializers.DateTimeField()
    channel = serializers.CharField(max_length=255)
    hostname = serializers.CharField(max_length=255)
    
    # Optional but important fields
    event_record_id = serializers.IntegerField(required=False, allow_null=True)
    provider_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    provider_guid = serializers.CharField(max_length=50, required=False, allow_blank=True)
    level = serializers.IntegerField(required=False, default=0)
    level_name = serializers.CharField(max_length=50, required=False, allow_blank=True)
    task = serializers.IntegerField(required=False, default=0)
    task_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    opcode = serializers.IntegerField(required=False, default=0)
    opcode_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    keywords = serializers.CharField(max_length=255, required=False, allow_blank=True)
    
    # Full event content
    message = serializers.CharField(required=False, allow_blank=True)
    raw_xml = serializers.CharField(required=False, allow_blank=True)
    event_data = serializers.JSONField(required=False, default=dict)
    user_data = serializers.JSONField(required=False, default=dict)
    system_data = serializers.JSONField(required=False, default=dict)
    
    # Extracted user info
    user_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    user_domain = serializers.CharField(max_length=255, required=False, allow_blank=True)
    user_sid = serializers.CharField(max_length=100, required=False, allow_blank=True)
    target_user_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    target_user_domain = serializers.CharField(max_length=255, required=False, allow_blank=True)
    target_user_sid = serializers.CharField(max_length=100, required=False, allow_blank=True)
    
    # Process info
    process_id = serializers.IntegerField(required=False, allow_null=True)
    process_name = serializers.CharField(max_length=500, required=False, allow_blank=True)
    process_path = serializers.CharField(required=False, allow_blank=True)
    command_line = serializers.CharField(required=False, allow_blank=True)
    parent_process_id = serializers.IntegerField(required=False, allow_null=True)
    parent_process_name = serializers.CharField(max_length=500, required=False, allow_blank=True)
    parent_command_line = serializers.CharField(required=False, allow_blank=True)
    
    # Network info
    source_ip = serializers.IPAddressField(required=False, allow_null=True)
    source_port = serializers.IntegerField(required=False, allow_null=True)
    destination_ip = serializers.IPAddressField(required=False, allow_null=True)
    destination_port = serializers.IntegerField(required=False, allow_null=True)
    protocol = serializers.CharField(max_length=20, required=False, allow_blank=True)
    
    # Logon info
    logon_type = serializers.IntegerField(required=False, allow_null=True)
    logon_type_name = serializers.CharField(max_length=50, required=False, allow_blank=True)
    logon_id = serializers.CharField(max_length=50, required=False, allow_blank=True)
    authentication_package = serializers.CharField(max_length=100, required=False, allow_blank=True)
    workstation_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    
    # Object/File info
    object_name = serializers.CharField(required=False, allow_blank=True)
    object_type = serializers.CharField(max_length=100, required=False, allow_blank=True)
    access_mask = serializers.CharField(max_length=50, required=False, allow_blank=True)
    
    # Service info
    service_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    service_type = serializers.CharField(max_length=100, required=False, allow_blank=True)
    service_start_type = serializers.CharField(max_length=50, required=False, allow_blank=True)
    service_account = serializers.CharField(max_length=255, required=False, allow_blank=True)
    
    # AD info
    object_dn = serializers.CharField(required=False, allow_blank=True)
    object_guid = serializers.CharField(max_length=50, required=False, allow_blank=True)
    object_class = serializers.CharField(max_length=100, required=False, allow_blank=True)
    
    # Hashes
    file_hash_md5 = serializers.CharField(max_length=32, required=False, allow_blank=True)
    file_hash_sha1 = serializers.CharField(max_length=40, required=False, allow_blank=True)
    file_hash_sha256 = serializers.CharField(max_length=64, required=False, allow_blank=True)
    
    # Status
    status = serializers.CharField(max_length=50, required=False, allow_blank=True)
    status_code = serializers.CharField(max_length=20, required=False, allow_blank=True)
    failure_reason = serializers.CharField(max_length=255, required=False, allow_blank=True)


class BulkIngestSerializer(serializers.Serializer):
    """Bulk event ingestion from agents"""
    agent_id = serializers.CharField(max_length=100)
    agent_hostname = serializers.CharField(max_length=255)
    agent_ip = serializers.IPAddressField(required=False, allow_null=True)
    batch_timestamp = serializers.DateTimeField()
    events = EventIngestSerializer(many=True)
    
    def validate_events(self, value):
        if len(value) > 5000:
            raise serializers.ValidationError("Maximum 5000 events per batch")
        return value

