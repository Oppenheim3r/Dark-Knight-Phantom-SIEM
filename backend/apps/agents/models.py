"""
Dark Knight Phantom SIEM - Agent Models
Manages Phantom Agent registration, configuration, and health
"""
from django.db import models
from django.utils import timezone
from datetime import timedelta
import uuid


class Agent(models.Model):
    """
    Represents a Phantom Agent installed on a Windows endpoint
    """
    STATUS_CHOICES = [
        ('ONLINE', 'Online'),
        ('OFFLINE', 'Offline'),
        ('DEGRADED', 'Degraded'),
        ('UNKNOWN', 'Unknown'),
    ]
    
    OS_CHOICES = [
        ('WINDOWS_10', 'Windows 10'),
        ('WINDOWS_11', 'Windows 11'),
        ('WINDOWS_SERVER_2016', 'Windows Server 2016'),
        ('WINDOWS_SERVER_2019', 'Windows Server 2019'),
        ('WINDOWS_SERVER_2022', 'Windows Server 2022'),
        ('WINDOWS_SERVER_2025', 'Windows Server 2025'),
        ('OTHER', 'Other'),
    ]
    
    ROLE_CHOICES = [
        ('WORKSTATION', 'Workstation'),
        ('MEMBER_SERVER', 'Member Server'),
        ('DOMAIN_CONTROLLER', 'Domain Controller'),
        ('DNS_SERVER', 'DNS Server'),
        ('DHCP_SERVER', 'DHCP Server'),
        ('FILE_SERVER', 'File Server'),
        ('WEB_SERVER', 'Web Server (IIS)'),
        ('CERTIFICATE_AUTHORITY', 'Certificate Authority'),
        ('HYPER_V_HOST', 'Hyper-V Host'),
        ('OTHER', 'Other'),
    ]
    
    # Identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent_id = models.CharField(max_length=100, unique=True, db_index=True)
    hostname = models.CharField(max_length=255, db_index=True)
    domain = models.CharField(max_length=255, blank=True, db_index=True)
    fqdn = models.CharField(max_length=500, blank=True)
    
    # Network Information
    ip_address = models.GenericIPAddressField(db_index=True)
    mac_address = models.CharField(max_length=17, blank=True)
    
    # System Information
    os_type = models.CharField(max_length=50, choices=OS_CHOICES, default='OTHER')
    os_version = models.CharField(max_length=100, blank=True)
    os_build = models.CharField(max_length=50, blank=True)
    architecture = models.CharField(max_length=20, default='x64')
    server_role = models.CharField(max_length=50, choices=ROLE_CHOICES, default='WORKSTATION')
    is_domain_controller = models.BooleanField(default=False)
    
    # Agent Information
    agent_version = models.CharField(max_length=20)
    install_date = models.DateTimeField(auto_now_add=True)
    last_config_update = models.DateTimeField(auto_now=True)
    
    # Status and Health
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='UNKNOWN')
    last_heartbeat = models.DateTimeField(null=True, blank=True)
    last_event_time = models.DateTimeField(null=True, blank=True)
    events_sent_total = models.BigIntegerField(default=0)
    events_sent_today = models.IntegerField(default=0)
    
    # Configuration
    config = models.JSONField(default=dict, blank=True)
    enabled_channels = models.JSONField(default=list, blank=True)  # List of log channels to collect
    collection_interval = models.IntegerField(default=10)  # seconds
    batch_size = models.IntegerField(default=500)
    
    # Tags and Metadata
    tags = models.JSONField(default=list, blank=True)
    description = models.TextField(blank=True)
    location = models.CharField(max_length=255, blank=True)
    
    # Activation
    is_active = models.BooleanField(default=True)
    api_key = models.CharField(max_length=100, blank=True)  # Agent authentication
    
    class Meta:
        db_table = 'agents'
        ordering = ['hostname']
    
    def __str__(self):
        return f"{self.hostname} ({self.agent_id})"
    
    @property
    def is_online(self):
        """Check if agent is online based on last heartbeat"""
        if not self.last_heartbeat:
            return False
        threshold = timezone.now() - timedelta(minutes=2)
        return self.last_heartbeat > threshold
    
    def update_status(self):
        """Update agent status based on heartbeat"""
        if self.is_online:
            self.status = 'ONLINE'
        elif self.last_heartbeat and self.last_heartbeat > timezone.now() - timedelta(minutes=5):
            self.status = 'DEGRADED'
        else:
            self.status = 'OFFLINE'
        self.save(update_fields=['status'])


class AgentHeartbeat(models.Model):
    """
    Stores agent heartbeat history for monitoring
    """
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='heartbeats')
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    
    # System Metrics
    cpu_percent = models.FloatField(default=0)
    memory_percent = models.FloatField(default=0)
    disk_percent = models.FloatField(default=0)
    
    # Agent Metrics
    events_in_queue = models.IntegerField(default=0)
    events_sent = models.IntegerField(default=0)
    errors_count = models.IntegerField(default=0)
    
    # Status
    is_healthy = models.BooleanField(default=True)
    message = models.CharField(max_length=500, blank=True)
    
    class Meta:
        db_table = 'agent_heartbeats'
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"Heartbeat: {self.agent.hostname} at {self.timestamp}"


class AgentLogChannel(models.Model):
    """
    Represents a Windows Event Log channel configuration
    """
    name = models.CharField(max_length=255, unique=True)
    display_name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=100, blank=True)  # Security, System, AD, etc.
    is_default = models.BooleanField(default=False)  # Enabled by default for new agents
    is_critical = models.BooleanField(default=False)  # Critical security channel
    
    # Collection settings
    default_filter = models.JSONField(default=dict, blank=True)  # Default event ID filters
    
    class Meta:
        db_table = 'agent_log_channels'
        ordering = ['category', 'name']
    
    def __str__(self):
        return self.display_name


class AgentCommand(models.Model):
    """
    Commands to be sent to agents (configuration updates, etc.)
    """
    COMMAND_TYPES = [
        ('UPDATE_CONFIG', 'Update Configuration'),
        ('RESTART', 'Restart Agent'),
        ('UPDATE_CHANNELS', 'Update Log Channels'),
        ('COLLECT_NOW', 'Force Collection'),
        ('STOP', 'Stop Agent'),
        ('START', 'Start Agent'),
    ]
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('SENT', 'Sent'),
        ('ACKNOWLEDGED', 'Acknowledged'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]
    
    agent = models.ForeignKey(Agent, on_delete=models.CASCADE, related_name='commands')
    command_type = models.CharField(max_length=50, choices=COMMAND_TYPES)
    payload = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    result = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        db_table = 'agent_commands'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.command_type} for {self.agent.hostname}"



