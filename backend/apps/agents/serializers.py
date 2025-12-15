"""
Dark Knight Phantom SIEM - Agent Serializers
"""
from rest_framework import serializers
from django.utils import timezone
from .models import Agent, AgentHeartbeat, AgentLogChannel, AgentCommand


class AgentSerializer(serializers.ModelSerializer):
    is_online = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = Agent
        fields = '__all__'
        read_only_fields = ['id', 'install_date', 'last_heartbeat', 'events_sent_total']


class AgentListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views"""
    is_online = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = Agent
        fields = [
            'id', 'agent_id', 'hostname', 'domain', 'ip_address',
            'os_type', 'server_role', 'is_domain_controller',
            'status', 'is_online', 'last_heartbeat', 'agent_version',
            'events_sent_today', 'is_active'
        ]


class AgentRegistrationSerializer(serializers.Serializer):
    """Serializer for agent registration"""
    hostname = serializers.CharField(max_length=255)
    domain = serializers.CharField(max_length=255, required=False, allow_blank=True)
    fqdn = serializers.CharField(max_length=500, required=False, allow_blank=True)
    ip_address = serializers.IPAddressField()
    mac_address = serializers.CharField(max_length=17, required=False, allow_blank=True)
    os_type = serializers.CharField(max_length=50, required=False)
    os_version = serializers.CharField(max_length=100, required=False, allow_blank=True)
    os_build = serializers.CharField(max_length=50, required=False, allow_blank=True)
    architecture = serializers.CharField(max_length=20, required=False, default='x64')
    is_domain_controller = serializers.BooleanField(required=False, default=False)
    server_role = serializers.CharField(max_length=50, required=False, default='WORKSTATION')
    agent_version = serializers.CharField(max_length=20)
    enabled_channels = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True
    )
    
    def create(self, validated_data):
        import uuid
        hostname = validated_data['hostname']
        
        # Check if agent already exists
        try:
            agent = Agent.objects.get(hostname=hostname)
            # Update existing agent
            agent.domain = validated_data.get('domain', agent.domain)
            agent.fqdn = validated_data.get('fqdn', agent.fqdn)
            agent.ip_address = validated_data['ip_address']
            agent.mac_address = validated_data.get('mac_address', agent.mac_address)
            agent.os_type = validated_data.get('os_type', agent.os_type)
            agent.os_version = validated_data.get('os_version', agent.os_version)
            agent.os_build = validated_data.get('os_build', agent.os_build)
            agent.architecture = validated_data.get('architecture', agent.architecture)
            agent.is_domain_controller = validated_data.get('is_domain_controller', agent.is_domain_controller)
            agent.server_role = validated_data.get('server_role', agent.server_role)
            agent.agent_version = validated_data['agent_version']
            agent.enabled_channels = validated_data.get('enabled_channels', agent.enabled_channels or [])
            agent.status = 'ONLINE'
            agent.last_heartbeat = timezone.now()
            agent.save()
        except Agent.DoesNotExist:
            # Create new agent with unique ID (only generated once)
            agent_id = f"phantom-{hostname.lower()}-{str(uuid.uuid4())[:8]}"
            agent = Agent.objects.create(
                agent_id=agent_id,
                hostname=hostname,
                domain=validated_data.get('domain', ''),
                fqdn=validated_data.get('fqdn', ''),
                ip_address=validated_data['ip_address'],
                mac_address=validated_data.get('mac_address', ''),
                os_type=validated_data.get('os_type', 'OTHER'),
                os_version=validated_data.get('os_version', ''),
                os_build=validated_data.get('os_build', ''),
                architecture=validated_data.get('architecture', 'x64'),
                is_domain_controller=validated_data.get('is_domain_controller', False),
                server_role=validated_data.get('server_role', 'WORKSTATION'),
                agent_version=validated_data['agent_version'],
                enabled_channels=validated_data.get('enabled_channels', []),
                status='ONLINE',
                last_heartbeat=timezone.now(),
            )
        return agent


class AgentHeartbeatSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentHeartbeat
        fields = '__all__'
        read_only_fields = ['agent', 'timestamp']


class HeartbeatSubmitSerializer(serializers.Serializer):
    """Serializer for heartbeat submission from agents"""
    agent_id = serializers.CharField(max_length=100)
    cpu_percent = serializers.FloatField(required=False, default=0)
    memory_percent = serializers.FloatField(required=False, default=0)
    disk_percent = serializers.FloatField(required=False, default=0)
    events_in_queue = serializers.IntegerField(required=False, default=0)
    events_sent = serializers.IntegerField(required=False, default=0)
    errors_count = serializers.IntegerField(required=False, default=0)
    is_healthy = serializers.BooleanField(required=False, default=True)
    message = serializers.CharField(max_length=500, required=False, allow_blank=True)


class AgentLogChannelSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentLogChannel
        fields = '__all__'


class AgentCommandSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentCommand
        fields = '__all__'
        read_only_fields = ['created_at', 'sent_at', 'completed_at']

