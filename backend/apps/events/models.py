"""
Dark Knight Phantom SIEM - Event Models
Comprehensive Windows Event Log storage with FULL event data
"""
from django.db import models
from django.utils import timezone
import json


class EventSource(models.Model):
    """
    Represents a log source/channel
    Examples: Security, System, Application, Sysmon, PowerShell, etc.
    """
    name = models.CharField(max_length=255, unique=True)
    provider = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'event_sources'
        ordering = ['name']
    
    def __str__(self):
        return self.name


class EventCategory(models.Model):
    """
    Event categories for classification
    """
    CATEGORY_CHOICES = [
        ('AUTHENTICATION', 'Authentication'),
        ('AUTHORIZATION', 'Authorization'),
        ('PROCESS', 'Process Execution'),
        ('NETWORK', 'Network Activity'),
        ('FILE', 'File System'),
        ('REGISTRY', 'Registry'),
        ('SERVICE', 'Service'),
        ('SCHEDULED_TASK', 'Scheduled Task'),
        ('ACCOUNT_MANAGEMENT', 'Account Management'),
        ('GROUP_POLICY', 'Group Policy'),
        ('ACTIVE_DIRECTORY', 'Active Directory'),
        ('KERBEROS', 'Kerberos'),
        ('POWERSHELL', 'PowerShell'),
        ('WMI', 'WMI'),
        ('DNS', 'DNS'),
        ('DHCP', 'DHCP'),
        ('FIREWALL', 'Firewall'),
        ('DEFENDER', 'Windows Defender'),
        ('CERTIFICATE', 'Certificate Services'),
        ('RDP', 'Remote Desktop'),
        ('SMB', 'SMB/File Share'),
        ('SYSMON', 'Sysmon'),
        ('OTHER', 'Other'),
    ]
    
    name = models.CharField(max_length=50, choices=CATEGORY_CHOICES, unique=True)
    description = models.TextField(blank=True)
    
    class Meta:
        db_table = 'event_categories'
        verbose_name_plural = 'Event Categories'
    
    def __str__(self):
        return self.name


class SecurityEvent(models.Model):
    """
    Core Security Event Model - Stores FULL event data
    This is the main table for all Windows Event Logs
    """
    SEVERITY_CHOICES = [
        ('INFO', 'Informational'),
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    # Event Identification
    event_id = models.IntegerField(db_index=True)
    event_record_id = models.BigIntegerField(null=True, blank=True)
    correlation_id = models.UUIDField(null=True, blank=True, db_index=True)
    
    # Timestamps
    timestamp = models.DateTimeField(db_index=True)
    received_at = models.DateTimeField(default=timezone.now, db_index=True)
    
    # Source Information
    source = models.ForeignKey(EventSource, on_delete=models.SET_NULL, null=True, related_name='events')
    channel = models.CharField(max_length=255, db_index=True)  # Security, System, Application, etc.
    provider_name = models.CharField(max_length=255, db_index=True)
    provider_guid = models.CharField(max_length=50, blank=True)
    
    # Host Information
    hostname = models.CharField(max_length=255, db_index=True)
    domain = models.CharField(max_length=255, blank=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    
    # Agent Information
    agent_id = models.CharField(max_length=100, db_index=True)
    
    # Event Classification
    category = models.ForeignKey(EventCategory, on_delete=models.SET_NULL, null=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='INFO', db_index=True)
    level = models.IntegerField(default=0)  # Windows Event Level (0-5)
    level_name = models.CharField(max_length=50, blank=True)  # Information, Warning, Error, etc.
    task = models.IntegerField(default=0)
    task_name = models.CharField(max_length=255, blank=True)
    opcode = models.IntegerField(default=0)
    opcode_name = models.CharField(max_length=100, blank=True)
    keywords = models.CharField(max_length=255, blank=True)
    
    # Event Content - FULL DATA
    message = models.TextField(blank=True)  # Formatted message
    raw_xml = models.TextField(blank=True)  # Original XML event data
    event_data = models.JSONField(default=dict)  # Parsed EventData as JSON
    user_data = models.JSONField(default=dict, blank=True)  # Parsed UserData as JSON
    system_data = models.JSONField(default=dict, blank=True)  # System metadata
    
    # User Information (extracted for quick queries)
    user_name = models.CharField(max_length=255, blank=True, db_index=True)
    user_domain = models.CharField(max_length=255, blank=True)
    user_sid = models.CharField(max_length=100, blank=True, db_index=True)
    target_user_name = models.CharField(max_length=255, blank=True, db_index=True)
    target_user_domain = models.CharField(max_length=255, blank=True)
    target_user_sid = models.CharField(max_length=100, blank=True)
    
    # Process Information (for process events)
    process_id = models.IntegerField(null=True, blank=True, db_index=True)
    process_name = models.CharField(max_length=500, blank=True, db_index=True)
    process_path = models.TextField(blank=True)
    command_line = models.TextField(blank=True)
    parent_process_id = models.IntegerField(null=True, blank=True)
    parent_process_name = models.CharField(max_length=500, blank=True)
    parent_command_line = models.TextField(blank=True)
    
    # Network Information (for network events)
    source_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    source_port = models.IntegerField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    destination_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=20, blank=True)
    
    # Logon Information (for authentication events)
    logon_type = models.IntegerField(null=True, blank=True)
    logon_type_name = models.CharField(max_length=50, blank=True)
    logon_id = models.CharField(max_length=50, blank=True)
    authentication_package = models.CharField(max_length=100, blank=True)
    workstation_name = models.CharField(max_length=255, blank=True)
    
    # File/Object Information (for file events)
    object_name = models.TextField(blank=True)
    object_type = models.CharField(max_length=100, blank=True)
    access_mask = models.CharField(max_length=50, blank=True)
    
    # Service Information (for service events)
    service_name = models.CharField(max_length=255, blank=True, db_index=True)
    service_type = models.CharField(max_length=100, blank=True)
    service_start_type = models.CharField(max_length=50, blank=True)
    service_account = models.CharField(max_length=255, blank=True)
    
    # Active Directory Information
    object_dn = models.TextField(blank=True)  # Distinguished Name
    object_guid = models.CharField(max_length=50, blank=True)
    object_class = models.CharField(max_length=100, blank=True)
    attribute_name = models.CharField(max_length=255, blank=True)
    attribute_value = models.TextField(blank=True)
    
    # Kerberos Information
    ticket_encryption_type = models.CharField(max_length=50, blank=True)
    ticket_options = models.CharField(max_length=50, blank=True)
    service_name_kerberos = models.CharField(max_length=255, blank=True)
    
    # Hash Values (for Sysmon)
    file_hash_md5 = models.CharField(max_length=32, blank=True)
    file_hash_sha1 = models.CharField(max_length=40, blank=True)
    file_hash_sha256 = models.CharField(max_length=64, blank=True, db_index=True)
    
    # Status Information
    status = models.CharField(max_length=50, blank=True)
    status_code = models.CharField(max_length=20, blank=True)
    failure_reason = models.CharField(max_length=255, blank=True)
    
    # Indexing and Search
    full_text = models.TextField(blank=True)  # Combined searchable text
    tags = models.JSONField(default=list, blank=True)
    
    # Processing Status
    is_processed = models.BooleanField(default=False)
    is_alerted = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'security_events'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_id', 'timestamp']),
            models.Index(fields=['hostname', 'timestamp']),
            models.Index(fields=['channel', 'timestamp']),
            models.Index(fields=['severity', 'timestamp']),
            models.Index(fields=['user_name', 'timestamp']),
            models.Index(fields=['process_name', 'timestamp']),
            models.Index(fields=['source_ip', 'timestamp']),
            models.Index(fields=['agent_id', 'timestamp']),
        ]
    
    def __str__(self):
        return f"Event {self.event_id} - {self.hostname} - {self.timestamp}"
    
    def save(self, *args, **kwargs):
        # Build full-text search field
        searchable_parts = [
            str(self.event_id),
            self.hostname,
            self.message,
            self.user_name,
            self.process_name,
            self.command_line,
            self.service_name,
            str(self.source_ip) if self.source_ip else '',
            str(self.destination_ip) if self.destination_ip else '',
        ]
        self.full_text = ' '.join(filter(None, searchable_parts))
        super().save(*args, **kwargs)


class EventStatistics(models.Model):
    """
    Hourly statistics for dashboard performance
    """
    hour = models.DateTimeField(db_index=True)
    hostname = models.CharField(max_length=255, db_index=True)
    channel = models.CharField(max_length=255)
    event_id = models.IntegerField()
    count = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'event_statistics'
        unique_together = ['hour', 'hostname', 'channel', 'event_id']
        ordering = ['-hour']
    
    def __str__(self):
        return f"Stats: {self.hostname} - {self.event_id} - {self.hour}"


class RawEventBatch(models.Model):
    """
    Stores raw event batches for replay/reprocessing
    """
    agent_id = models.CharField(max_length=100, db_index=True)
    received_at = models.DateTimeField(auto_now_add=True, db_index=True)
    event_count = models.IntegerField(default=0)
    raw_data = models.BinaryField()  # Compressed JSON
    is_processed = models.BooleanField(default=False)
    processing_errors = models.TextField(blank=True)
    
    class Meta:
        db_table = 'raw_event_batches'
        ordering = ['-received_at']
    
    def __str__(self):
        return f"Batch from {self.agent_id} - {self.event_count} events"



