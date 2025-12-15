"""
Dark Knight Phantom SIEM - Alert Views
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta

from .models import Alert, AlertComment
from .serializers import (
    AlertSerializer,
    AlertListSerializer,
    AlertCreateSerializer,
    AlertCommentSerializer,
)


class AlertViewSet(viewsets.ModelViewSet):
    """API endpoints for alert management"""
    queryset = Alert.objects.all()
    search_fields = ['title', 'description', 'hostname', 'user_name', 'rule_name']
    ordering_fields = ['created_at', 'severity', 'status', 'hostname']
    ordering = ['-created_at']
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        hostname = self.request.query_params.get('hostname')
        if hostname:
            queryset = queryset.filter(hostname__icontains=hostname)
        
        return queryset
    
    def get_serializer_class(self):
        if self.action == 'list':
            return AlertListSerializer
        elif self.action == 'create':
            return AlertCreateSerializer
        return AlertSerializer
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get alert statistics"""
        hours = int(request.query_params.get('hours', 24))
        since = timezone.now() - timedelta(hours=hours)
        
        qs = self.queryset.filter(created_at__gte=since)
        
        by_severity = qs.values('severity').annotate(count=Count('id'))
        by_status = qs.values('status').annotate(count=Count('id'))
        
        return Response({
            'period_hours': hours,
            'total': qs.count(),
            'by_severity': {item['severity']: item['count'] for item in by_severity},
            'by_status': {item['status']: item['count'] for item in by_status},
            'new_count': qs.filter(status='NEW').count(),
            'critical_count': qs.filter(severity='CRITICAL', status='NEW').count(),
        })
    
    @action(detail=False, methods=['get'])
    def active(self, request):
        """Get active alerts (not resolved or closed)"""
        alerts = self.queryset.exclude(status__in=['RESOLVED', 'CLOSED', 'FALSE_POSITIVE'])
        serializer = AlertListSerializer(alerts[:100], many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def acknowledge(self, request, pk=None):
        """Acknowledge an alert"""
        alert = self.get_object()
        alert.status = 'ACKNOWLEDGED'
        alert.assigned_to = request.data.get('assigned_to', '')
        alert.save()
        
        # Add comment
        if request.data.get('comment'):
            AlertComment.objects.create(
                alert=alert,
                author=request.data.get('author', 'System'),
                content=request.data['comment']
            )
        
        return Response({'status': 'acknowledged'})
    
    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve an alert"""
        alert = self.get_object()
        alert.status = 'RESOLVED'
        alert.notes = request.data.get('notes', alert.notes)
        alert.save()
        
        return Response({'status': 'resolved'})
    
    @action(detail=True, methods=['post'])
    def add_comment(self, request, pk=None):
        """Add a comment to an alert"""
        alert = self.get_object()
        
        comment = AlertComment.objects.create(
            alert=alert,
            author=request.data.get('author', 'Anonymous'),
            content=request.data.get('content', '')
        )
        
        serializer = AlertCommentSerializer(comment)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class AlertCommentViewSet(viewsets.ModelViewSet):
    """API endpoints for alert comments"""
    queryset = AlertComment.objects.all()
    serializer_class = AlertCommentSerializer
    filterset_fields = ['alert', 'author']
    ordering = ['created_at']

