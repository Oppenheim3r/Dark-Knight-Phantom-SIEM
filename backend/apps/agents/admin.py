from django.contrib import admin
from .models import Agent, AgentHeartbeat, AgentLogChannel, AgentCommand

@admin.register(Agent)
class AgentAdmin(admin.ModelAdmin):
    list_display = ['hostname', 'agent_id', 'ip_address', 'status', 'os_type', 'server_role', 'last_heartbeat']
    list_filter = ['status', 'os_type', 'server_role', 'is_domain_controller', 'is_active']
    search_fields = ['hostname', 'agent_id', 'ip_address', 'domain']
    readonly_fields = ['id', 'install_date', 'last_heartbeat']

@admin.register(AgentHeartbeat)
class AgentHeartbeatAdmin(admin.ModelAdmin):
    list_display = ['agent', 'timestamp', 'cpu_percent', 'memory_percent', 'events_sent', 'is_healthy']
    list_filter = ['is_healthy', 'agent']
    date_hierarchy = 'timestamp'

@admin.register(AgentLogChannel)
class AgentLogChannelAdmin(admin.ModelAdmin):
    list_display = ['name', 'display_name', 'category', 'is_default', 'is_critical']
    list_filter = ['category', 'is_default', 'is_critical']
    search_fields = ['name', 'display_name']

@admin.register(AgentCommand)
class AgentCommandAdmin(admin.ModelAdmin):
    list_display = ['agent', 'command_type', 'status', 'created_at', 'completed_at']
    list_filter = ['command_type', 'status']



