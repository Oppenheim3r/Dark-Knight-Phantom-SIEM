"""
Dark Knight Phantom SIEM - Event Views
REST API endpoints for event management and ingestion
"""
from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from django.db.models import Count, Q
from django.db import transaction
from datetime import timedelta
import logging

from .models import SecurityEvent, EventSource, EventCategory, EventStatistics
from .serializers import (
    SecurityEventSerializer,
    SecurityEventListSerializer,
    SecurityEventCreateSerializer,
    EventSourceSerializer,
    EventCategorySerializer,
    BulkIngestSerializer,
    EventIngestSerializer,
)

logger = logging.getLogger(__name__)


class EventSourceViewSet(viewsets.ModelViewSet):
    """API endpoints for event sources"""
    queryset = EventSource.objects.all()
    serializer_class = EventSourceSerializer
    search_fields = ['name', 'provider', 'description']


class EventCategoryViewSet(viewsets.ModelViewSet):
    """API endpoints for event categories"""
    queryset = EventCategory.objects.all()
    serializer_class = EventCategorySerializer


class SecurityEventViewSet(viewsets.ModelViewSet):
    """
    API endpoints for security events
    Supports filtering, searching, and ordering
    """
    queryset = SecurityEvent.objects.select_related('source', 'category').all()
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['message', 'full_text', 'hostname', 'user_name', 'command_line', 'process_name', 'process_path', 'raw_xml']
    ordering_fields = ['timestamp', 'event_id', 'hostname', 'severity']
    ordering = ['-timestamp']
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Manual filtering
        event_id = self.request.query_params.get('event_id')
        if event_id:
            queryset = queryset.filter(event_id=event_id)
        
        hostname = self.request.query_params.get('hostname')
        if hostname:
            queryset = queryset.filter(hostname__icontains=hostname)
        
        channel = self.request.query_params.get('channel')
        if channel:
            queryset = queryset.filter(channel=channel)
        
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        agent_id = self.request.query_params.get('agent_id')
        if agent_id:
            queryset = queryset.filter(agent_id=agent_id)
        
        user_name = self.request.query_params.get('user_name')
        if user_name:
            queryset = queryset.filter(user_name__icontains=user_name)
        
        source_ip = self.request.query_params.get('source_ip')
        if source_ip:
            queryset = queryset.filter(source_ip=source_ip)
        
        timestamp_gte = self.request.query_params.get('timestamp__gte')
        if timestamp_gte:
            queryset = queryset.filter(timestamp__gte=timestamp_gte)
        
        timestamp_lte = self.request.query_params.get('timestamp__lte')
        if timestamp_lte:
            queryset = queryset.filter(timestamp__lte=timestamp_lte)
        
        return queryset
    
    def get_serializer_class(self):
        if self.action == 'list':
            return SecurityEventListSerializer
        elif self.action in ['create', 'update', 'partial_update']:
            return SecurityEventCreateSerializer
        return SecurityEventSerializer
    
    @action(detail=False, methods=['get'])
    def recent(self, request):
        """Get recent events (last hour)"""
        one_hour_ago = timezone.now() - timedelta(hours=1)
        events = self.queryset.filter(timestamp__gte=one_hour_ago)[:100]
        serializer = SecurityEventListSerializer(events, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def by_severity(self, request):
        """Get events grouped by severity"""
        severity = request.query_params.get('severity', 'CRITICAL')
        hours = int(request.query_params.get('hours', 24))
        since = timezone.now() - timedelta(hours=hours)
        
        events = self.queryset.filter(
            severity=severity,
            timestamp__gte=since
        )[:500]
        serializer = SecurityEventListSerializer(events, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get event statistics"""
        hours = int(request.query_params.get('hours', 24))
        since = timezone.now() - timedelta(hours=hours)
        
        stats = self.queryset.filter(timestamp__gte=since).aggregate(
            total=Count('id'),
            critical=Count('id', filter=Q(severity='CRITICAL')),
            high=Count('id', filter=Q(severity='HIGH')),
            medium=Count('id', filter=Q(severity='MEDIUM')),
            low=Count('id', filter=Q(severity='LOW')),
            info=Count('id', filter=Q(severity='INFO')),
        )
        
        # Top event IDs
        top_events = self.queryset.filter(
            timestamp__gte=since
        ).values('event_id').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        # Top hosts
        top_hosts = self.queryset.filter(
            timestamp__gte=since
        ).values('hostname').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        return Response({
            'period_hours': hours,
            'counts': stats,
            'top_event_ids': list(top_events),
            'top_hosts': list(top_hosts),
        })


class EventIngestView(APIView):
    """
    High-performance event ingestion endpoint
    Used by Phantom Agents to submit events
    """
    
    def post(self, request):
        """
        Ingest a batch of events from an agent
        """
        serializer = BulkIngestSerializer(data=request.data)
        
        if not serializer.is_valid():
            logger.warning(f"Invalid event batch: {serializer.errors}")
            return Response(
                {'error': 'Invalid data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        data = serializer.validated_data
        agent_id = data['agent_id']
        agent_hostname = data['agent_hostname']
        agent_ip = data.get('agent_ip')
        events_data = data['events']
        
        # Get or create event source
        source, _ = EventSource.objects.get_or_create(
            name='Windows Event Log',
            defaults={'provider': 'PhantomAgent', 'description': 'Windows Event Log collected by Phantom Agent'}
        )
        
        # Build event objects
        events_to_create = []
        for event_data in events_data:
            # Determine severity based on event characteristics
            severity = self._determine_severity(event_data)
            
            event = SecurityEvent(
                event_id=event_data['event_id'],
                event_record_id=event_data.get('event_record_id'),
                timestamp=event_data['timestamp'],
                source=source,
                channel=event_data['channel'],
                provider_name=event_data.get('provider_name', ''),
                provider_guid=event_data.get('provider_guid', ''),
                hostname=event_data['hostname'],
                domain=event_data.get('user_domain', ''),
                ip_address=agent_ip,
                agent_id=agent_id,
                severity=severity,
                level=event_data.get('level', 0),
                level_name=event_data.get('level_name', ''),
                task=event_data.get('task', 0),
                task_name=event_data.get('task_name', ''),
                opcode=event_data.get('opcode', 0),
                opcode_name=event_data.get('opcode_name', ''),
                keywords=event_data.get('keywords', ''),
                message=event_data.get('message', ''),
                raw_xml=event_data.get('raw_xml', ''),
                event_data=event_data.get('event_data', {}),
                user_data=event_data.get('user_data', {}),
                system_data=event_data.get('system_data', {}),
                user_name=event_data.get('user_name', ''),
                user_domain=event_data.get('user_domain', ''),
                user_sid=event_data.get('user_sid', ''),
                target_user_name=event_data.get('target_user_name', ''),
                target_user_domain=event_data.get('target_user_domain', ''),
                target_user_sid=event_data.get('target_user_sid', ''),
                process_id=event_data.get('process_id'),
                process_name=event_data.get('process_name', ''),
                process_path=event_data.get('process_path', ''),
                command_line=event_data.get('command_line', ''),
                parent_process_id=event_data.get('parent_process_id'),
                parent_process_name=event_data.get('parent_process_name', ''),
                parent_command_line=event_data.get('parent_command_line', ''),
                source_ip=event_data.get('source_ip'),
                source_port=event_data.get('source_port'),
                destination_ip=event_data.get('destination_ip'),
                destination_port=event_data.get('destination_port'),
                protocol=event_data.get('protocol', ''),
                logon_type=event_data.get('logon_type'),
                logon_type_name=event_data.get('logon_type_name', ''),
                logon_id=event_data.get('logon_id', ''),
                authentication_package=event_data.get('authentication_package', ''),
                workstation_name=event_data.get('workstation_name', ''),
                object_name=event_data.get('object_name', ''),
                object_type=event_data.get('object_type', ''),
                access_mask=event_data.get('access_mask', ''),
                service_name=event_data.get('service_name', ''),
                service_type=event_data.get('service_type', ''),
                service_start_type=event_data.get('service_start_type', ''),
                service_account=event_data.get('service_account', ''),
                object_dn=event_data.get('object_dn', ''),
                object_guid=event_data.get('object_guid', ''),
                object_class=event_data.get('object_class', ''),
                file_hash_md5=event_data.get('file_hash_md5', ''),
                file_hash_sha1=event_data.get('file_hash_sha1', ''),
                file_hash_sha256=event_data.get('file_hash_sha256', ''),
                status=event_data.get('status', ''),
                status_code=event_data.get('status_code', ''),
                failure_reason=event_data.get('failure_reason', ''),
            )
            events_to_create.append(event)
        
        # Bulk insert for performance
        try:
            with transaction.atomic():
                created_events = SecurityEvent.objects.bulk_create(events_to_create, batch_size=1000)
            
            logger.info(f"Ingested {len(created_events)} events from agent {agent_id}")
            
            # Run detection engine on ingested events
            alerts_created = 0
            try:
                from apps.detection.engine import process_event_detection
                for event in created_events:
                    alerts = process_event_detection(event)
                    alerts_created += len(alerts)
                
                if alerts_created > 0:
                    logger.warning(f"Detection engine created {alerts_created} alerts from batch")
            except Exception as det_error:
                logger.error(f"Detection engine error: {det_error}")
            
            return Response({
                'status': 'success',
                'message': f'Ingested {len(created_events)} events',
                'agent_id': agent_id,
                'count': len(created_events),
                'alerts_generated': alerts_created,
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Error ingesting events: {str(e)}")
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _determine_severity(self, event_data):
        """Determine event severity based on event ID and content"""
        event_id = event_data.get('event_id', 0)
        
        # Critical events
        critical_events = [
            4697, 4698, 4719, 4720, 4728, 4732, 4756,  # Account/Group changes
            7045,  # Service installed
            4688,  # Process creation (needs command line analysis)
            1102,  # Audit log cleared
            4662,  # AD object operation (DCSync)
        ]
        
        # High severity events
        high_events = [
            4625,  # Failed logon
            4648,  # Explicit credential logon
            4672,  # Special privileges assigned
            4724,  # Password reset attempt
            4740,  # Account lockout
            4768, 4769, 4771,  # Kerberos events
            5140, 5145,  # Share access
        ]
        
        # Medium severity events  
        medium_events = [
            4624,  # Successful logon
            4634,  # Logoff
            4688,  # Process creation
            4689,  # Process termination
            5156,  # Firewall connection
        ]
        
        if event_id in critical_events:
            return 'CRITICAL'
        elif event_id in high_events:
            return 'HIGH'
        elif event_id in medium_events:
            return 'MEDIUM'
        elif event_data.get('level', 0) >= 3:  # Warning or Error
            return 'MEDIUM'
        else:
            return 'INFO'


class SingleEventIngestView(APIView):
    """Single event ingestion endpoint"""
    
    def post(self, request):
        """Ingest a single event"""
        serializer = EventIngestSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        data = serializer.validated_data
        
        # Get or create event source
        source, _ = EventSource.objects.get_or_create(
            name='Windows Event Log',
            defaults={'provider': 'PhantomAgent'}
        )
        
        try:
            event = SecurityEvent.objects.create(
                source=source,
                agent_id=request.META.get('HTTP_X_AGENT_ID', 'unknown'),
                **data
            )
            
            return Response({
                'status': 'success',
                'event_id': event.id
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Error creating event: {str(e)}")
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

