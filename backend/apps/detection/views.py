"""
Dark Knight Phantom SIEM - Detection Views
API endpoints for detection rules and alerts
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
import logging

from .models import DetectionRule, DetectionAlert, EntityTracker, AlertSuppressionRule
from .serializers import (
    DetectionRuleSerializer, DetectionRuleListSerializer,
    DetectionAlertSerializer, DetectionAlertListSerializer,
    AlertUpdateSerializer, EntityTrackerSerializer,
    AlertSuppressionRuleSerializer, AlertStatsSerializer
)
from .builtin_rules import install_builtin_rules
from .engine import reload_rules

logger = logging.getLogger(__name__)


class DetectionRuleViewSet(viewsets.ModelViewSet):
    """API endpoints for detection rules"""
    queryset = DetectionRule.objects.all()
    search_fields = ['name', 'description', 'mitre_technique']
    ordering_fields = ['name', 'severity', 'category', 'total_alerts']
    ordering = ['category', 'name']
    
    def get_serializer_class(self):
        if self.action == 'list':
            return DetectionRuleListSerializer
        return DetectionRuleSerializer
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by category
        category = self.request.query_params.get('category')
        if category:
            queryset = queryset.filter(category=category)
        
        # Filter by severity
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by enabled status
        enabled = self.request.query_params.get('enabled')
        if enabled is not None:
            queryset = queryset.filter(enabled=enabled.lower() == 'true')
        
        # Filter by builtin
        builtin = self.request.query_params.get('builtin')
        if builtin is not None:
            queryset = queryset.filter(is_builtin=builtin.lower() == 'true')
        
        return queryset
    
    @action(detail=False, methods=['post'])
    def install_builtin(self, request):
        """Install or update built-in detection rules"""
        created, updated = install_builtin_rules()
        reload_rules()
        return Response({
            'status': 'success',
            'created': created,
            'updated': updated,
            'message': f'Installed {created} new rules, updated {updated} existing rules'
        })
    
    @action(detail=False, methods=['post'])
    def reload(self, request):
        """Reload detection rules into memory"""
        reload_rules()
        return Response({'status': 'success', 'message': 'Rules reloaded'})
    
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        """Toggle rule enabled status"""
        rule = self.get_object()
        rule.enabled = not rule.enabled
        rule.save(update_fields=['enabled'])
        reload_rules()
        return Response({
            'status': 'success',
            'enabled': rule.enabled
        })
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get rule statistics"""
        rules = self.get_queryset()
        
        by_category = rules.values('category').annotate(count=Count('id'))
        by_severity = rules.values('severity').annotate(count=Count('id'))
        
        total_alerts = sum(r.total_alerts for r in rules)
        total_fp = sum(r.false_positives for r in rules)
        
        return Response({
            'total_rules': rules.count(),
            'enabled': rules.filter(enabled=True).count(),
            'builtin': rules.filter(is_builtin=True).count(),
            'custom': rules.filter(is_builtin=False).count(),
            'by_category': list(by_category),
            'by_severity': list(by_severity),
            'total_alerts_generated': total_alerts,
            'total_false_positives': total_fp,
            'false_positive_rate': round((total_fp / total_alerts * 100), 2) if total_alerts > 0 else 0,
        })


class DetectionAlertViewSet(viewsets.ModelViewSet):
    """API endpoints for detection alerts"""
    queryset = DetectionAlert.objects.select_related('rule').all()
    search_fields = ['title', 'hostname', 'user_name', 'source_ip']
    ordering_fields = ['triggered_at', 'severity', 'status', 'confidence']
    ordering = ['-triggered_at']
    
    def get_serializer_class(self):
        if self.action == 'list':
            return DetectionAlertListSerializer
        return DetectionAlertSerializer
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by status
        alert_status = self.request.query_params.get('status')
        if alert_status:
            queryset = queryset.filter(status=alert_status)
        
        # Filter by severity
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by hostname
        hostname = self.request.query_params.get('hostname')
        if hostname:
            queryset = queryset.filter(hostname__icontains=hostname)
        
        # Filter by user
        user_name = self.request.query_params.get('user_name')
        if user_name:
            queryset = queryset.filter(user_name__icontains=user_name)
        
        # Filter by rule
        rule_id = self.request.query_params.get('rule')
        if rule_id:
            queryset = queryset.filter(rule_id=rule_id)
        
        # Filter by rule category
        category = self.request.query_params.get('rule__category')
        if category:
            queryset = queryset.filter(rule__category=category)
        
        # Filter by time range
        hours = self.request.query_params.get('hours')
        if hours:
            since = timezone.now() - timedelta(hours=int(hours))
            queryset = queryset.filter(triggered_at__gte=since)
        
        return queryset
    
    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        """Update alert status"""
        alert = self.get_object()
        serializer = AlertUpdateSerializer(data=request.data)
        
        if serializer.is_valid():
            data = serializer.validated_data
            alert.status = data['status']
            
            if data.get('notes'):
                alert.notes = data['notes']
            if data.get('assigned_to'):
                alert.assigned_to = data['assigned_to']
            if data.get('resolution_notes'):
                alert.resolution_notes = data['resolution_notes']
            
            if data['status'] in ['RESOLVED', 'FALSE_POSITIVE']:
                alert.resolved_at = timezone.now()
            
            # Update false positive count if marked as FP
            if data['status'] == 'FALSE_POSITIVE':
                alert.rule.false_positives += 1
                alert.rule.save(update_fields=['false_positives'])
            
            alert.save()
            return Response(DetectionAlertSerializer(alert).data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def bulk_update(self, request):
        """Bulk update alert status"""
        alert_ids = request.data.get('alert_ids', [])
        new_status = request.data.get('status')
        
        if not alert_ids or not new_status:
            return Response(
                {'error': 'alert_ids and status are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        updated = DetectionAlert.objects.filter(id__in=alert_ids).update(
            status=new_status,
            resolved_at=timezone.now() if new_status in ['RESOLVED', 'FALSE_POSITIVE'] else None
        )
        
        return Response({
            'status': 'success',
            'updated': updated
        })
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get alert statistics"""
        hours = int(request.query_params.get('hours', 24))
        since = timezone.now() - timedelta(hours=hours)
        
        queryset = self.get_queryset()
        recent = queryset.filter(triggered_at__gte=since)
        
        by_severity = {
            'CRITICAL': queryset.filter(severity='CRITICAL').count(),
            'HIGH': queryset.filter(severity='HIGH').count(),
            'MEDIUM': queryset.filter(severity='MEDIUM').count(),
            'LOW': queryset.filter(severity='LOW').count(),
        }
        
        by_category = queryset.values('rule__category').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        stats = {
            'total': queryset.count(),
            'new': queryset.filter(status='NEW').count(),
            'investigating': queryset.filter(status='INVESTIGATING').count(),
            'resolved': queryset.filter(status='RESOLVED').count(),
            'false_positive': queryset.filter(status='FALSE_POSITIVE').count(),
            'by_severity': by_severity,
            'by_category': list(by_category),
            'recent_24h': recent.count(),
        }
        
        return Response(stats)
    
    @action(detail=False, methods=['get'])
    def timeline(self, request):
        """Get alerts timeline for dashboard"""
        hours = int(request.query_params.get('hours', 24))
        since = timezone.now() - timedelta(hours=hours)
        
        alerts = self.get_queryset().filter(triggered_at__gte=since)
        
        # Group by hour
        from django.db.models.functions import TruncHour
        hourly = alerts.annotate(
            hour=TruncHour('triggered_at')
        ).values('hour').annotate(
            count=Count('id')
        ).order_by('hour')
        
        return Response({
            'timeline': list(hourly),
            'total': alerts.count()
        })


class AlertSuppressionViewSet(viewsets.ModelViewSet):
    """API endpoints for alert suppression rules"""
    queryset = AlertSuppressionRule.objects.all()
    serializer_class = AlertSuppressionRuleSerializer
    ordering = ['-created_at']


class EntityTrackerViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoints for viewing entity tracking data"""
    queryset = EntityTracker.objects.all()
    serializer_class = EntityTrackerSerializer
    ordering = ['-last_event_time']
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        entity_type = self.request.query_params.get('entity_type')
        if entity_type:
            queryset = queryset.filter(entity_type=entity_type.upper())
        
        entity_value = self.request.query_params.get('entity_value')
        if entity_value:
            queryset = queryset.filter(entity_value__icontains=entity_value)
        
        # Only show recent trackers
        hours = int(self.request.query_params.get('hours', 1))
        since = timezone.now() - timedelta(hours=hours)
        queryset = queryset.filter(window_start__gte=since)
        
        return queryset


class DetectionTestView(APIView):
    """Test detection rules against sample events"""
    
    def post(self, request):
        """Test a rule against sample event data"""
        rule_id = request.data.get('rule_id')
        event_data = request.data.get('event')
        
        if not rule_id or not event_data:
            return Response(
                {'error': 'rule_id and event data are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            rule = DetectionRule.objects.get(id=rule_id)
        except DetectionRule.DoesNotExist:
            return Response(
                {'error': 'Rule not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Create a mock event (don't save)
        from apps.events.models import SecurityEvent
        event = SecurityEvent(**event_data)
        
        # Test against rule
        from .engine import get_engine
        engine = get_engine()
        
        # This would need more sophisticated testing logic
        result = {
            'rule': rule.name,
            'would_trigger': False,
            'reason': 'Test mode - full evaluation not implemented',
            'logic': rule.logic
        }
        
        return Response(result)

