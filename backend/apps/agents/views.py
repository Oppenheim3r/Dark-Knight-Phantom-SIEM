"""
Dark Knight Phantom SIEM - Agent Views
REST API endpoints for agent management
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from django.db.models import Count, Sum
from datetime import timedelta
import logging

from .models import Agent, AgentHeartbeat, AgentLogChannel, AgentCommand
from .serializers import (
    AgentSerializer,
    AgentListSerializer,
    AgentRegistrationSerializer,
    AgentHeartbeatSerializer,
    HeartbeatSubmitSerializer,
    AgentLogChannelSerializer,
    AgentCommandSerializer,
)

logger = logging.getLogger(__name__)


class AgentViewSet(viewsets.ModelViewSet):
    """API endpoints for agent management"""
    queryset = Agent.objects.all()
    search_fields = ['hostname', 'domain', 'ip_address', 'agent_id']
    ordering_fields = ['hostname', 'last_heartbeat', 'status', 'events_sent_today']
    ordering = ['hostname']
    
    def get_queryset(self):
        # Update status for agents based on last heartbeat before returning
        from datetime import timedelta
        threshold_online = timezone.now() - timedelta(minutes=2)
        threshold_degraded = timezone.now() - timedelta(minutes=5)
        
        # Mark agents as OFFLINE if no heartbeat in 2+ minutes
        Agent.objects.filter(
            last_heartbeat__lt=threshold_online,
            status='ONLINE'
        ).update(status='OFFLINE')
        
        # Mark agents as DEGRADED if heartbeat is 2-5 minutes old
        Agent.objects.filter(
            last_heartbeat__gte=threshold_degraded,
            last_heartbeat__lt=threshold_online,
            status__in=['ONLINE', 'UNKNOWN']
        ).update(status='DEGRADED')
        queryset = super().get_queryset()
        
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        os_type = self.request.query_params.get('os_type')
        if os_type:
            queryset = queryset.filter(os_type=os_type)
        
        is_active = self.request.query_params.get('is_active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        return queryset
    
    def get_serializer_class(self):
        if self.action == 'list':
            return AgentListSerializer
        return AgentSerializer
    
    @action(detail=False, methods=['get'])
    def online(self, request):
        """Get all online agents"""
        threshold = timezone.now() - timedelta(minutes=2)
        agents = self.queryset.filter(last_heartbeat__gte=threshold, is_active=True)
        serializer = AgentListSerializer(agents, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def offline(self, request):
        """Get all offline agents"""
        threshold = timezone.now() - timedelta(minutes=5)
        agents = self.queryset.filter(
            last_heartbeat__lt=threshold,
            is_active=True
        ) | self.queryset.filter(last_heartbeat__isnull=True, is_active=True)
        serializer = AgentListSerializer(agents, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get agent statistics"""
        total = self.queryset.filter(is_active=True).count()
        threshold = timezone.now() - timedelta(minutes=2)
        online = self.queryset.filter(last_heartbeat__gte=threshold, is_active=True).count()
        
        by_role = self.queryset.filter(is_active=True).values('server_role').annotate(
            count=Count('id')
        )
        
        by_os = self.queryset.filter(is_active=True).values('os_type').annotate(
            count=Count('id')
        )
        
        events_today = self.queryset.filter(is_active=True).aggregate(
            total=Sum('events_sent_today')
        )['total'] or 0
        
        return Response({
            'total_agents': total,
            'online': online,
            'offline': total - online,
            'by_role': list(by_role),
            'by_os': list(by_os),
            'events_sent_today': events_today,
        })
    
    @action(detail=True, methods=['get'])
    def heartbeats(self, request, pk=None):
        """Get agent heartbeat history"""
        agent = self.get_object()
        hours = int(request.query_params.get('hours', 24))
        since = timezone.now() - timedelta(hours=hours)
        
        heartbeats = agent.heartbeats.filter(timestamp__gte=since).order_by('-timestamp')[:100]
        serializer = AgentHeartbeatSerializer(heartbeats, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def commands(self, request, pk=None):
        """Get pending commands for agent"""
        agent = self.get_object()
        commands = agent.commands.filter(status__in=['PENDING', 'SENT'])
        serializer = AgentCommandSerializer(commands, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def send_command(self, request, pk=None):
        """Send a command to the agent"""
        agent = self.get_object()
        command_type = request.data.get('command_type')
        payload = request.data.get('payload', {})
        
        if not command_type:
            return Response(
                {'error': 'command_type is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        command = AgentCommand.objects.create(
            agent=agent,
            command_type=command_type,
            payload=payload
        )
        
        return Response({
            'status': 'success',
            'command_id': command.id
        })


class AgentRegistrationView(APIView):
    """
    Agent registration endpoint
    Called by agents on first startup
    """
    
    def post(self, request):
        serializer = AgentRegistrationSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid registration data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        agent = serializer.save()
        
        logger.info(f"Agent registered: {agent.hostname} ({agent.agent_id})")
        
        # Only include enabled_channels if we have server-side config
        # Otherwise let the agent use its defaults
        config = {
            'collection_interval': agent.collection_interval,
            'batch_size': agent.batch_size,
            'server_url': request.build_absolute_uri('/api/v1/'),
        }
        
        # Get default log channels if any are configured
        default_channels = AgentLogChannel.objects.filter(is_default=True).values_list('name', flat=True)
        if default_channels:
            config['enabled_channels'] = list(default_channels)
        
        return Response({
            'status': 'success',
            'agent_id': agent.agent_id,
            'config': config
        }, status=status.HTTP_201_CREATED)


class AgentHeartbeatView(APIView):
    """
    Agent heartbeat endpoint
    Called periodically by agents to report status
    """
    
    def post(self, request):
        serializer = HeartbeatSubmitSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid heartbeat data'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        data = serializer.validated_data
        agent_id = data['agent_id']
        
        try:
            agent = Agent.objects.get(agent_id=agent_id)
        except Agent.DoesNotExist:
            return Response(
                {'error': 'Agent not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Update agent status
        agent.last_heartbeat = timezone.now()
        agent.status = 'ONLINE'
        agent.events_sent_today += data.get('events_sent', 0)
        agent.events_sent_total += data.get('events_sent', 0)
        agent.save()
        
        # Record heartbeat
        heartbeat = AgentHeartbeat.objects.create(
            agent=agent,
            cpu_percent=data.get('cpu_percent', 0),
            memory_percent=data.get('memory_percent', 0),
            disk_percent=data.get('disk_percent', 0),
            events_in_queue=data.get('events_in_queue', 0),
            events_sent=data.get('events_sent', 0),
            errors_count=data.get('errors_count', 0),
            is_healthy=data.get('is_healthy', True),
            message=data.get('message', ''),
        )
        
        # Check for pending commands
        pending_commands = AgentCommand.objects.filter(
            agent=agent,
            status='PENDING'
        ).values('id', 'command_type', 'payload')
        
        # Mark commands as sent
        AgentCommand.objects.filter(
            agent=agent,
            status='PENDING'
        ).update(status='SENT', sent_at=timezone.now())
        
        return Response({
            'status': 'ok',
            'server_time': timezone.now().isoformat(),
            'commands': list(pending_commands),
            'config_update': agent.config if agent.config else None,
        })


class AgentLogChannelViewSet(viewsets.ModelViewSet):
    """API endpoints for log channel configuration"""
    queryset = AgentLogChannel.objects.all()
    serializer_class = AgentLogChannelSerializer
    search_fields = ['name', 'display_name', 'description']


class AgentCommandViewSet(viewsets.ModelViewSet):
    """API endpoints for agent commands"""
    queryset = AgentCommand.objects.all()
    serializer_class = AgentCommandSerializer
    ordering = ['-created_at']

