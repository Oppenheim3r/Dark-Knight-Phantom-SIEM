"""
Dark Knight Phantom SIEM - Dashboard Views
"""
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import render
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta

from apps.events.models import SecurityEvent
from apps.agents.models import Agent
from apps.detection.models import DetectionAlert


class DashboardStatsView(APIView):
    """Dashboard statistics API"""
    
    def get(self, request):
        hours = int(request.query_params.get('hours', 24))
        since = timezone.now() - timedelta(hours=hours)
        
        # Event counts
        events_qs = SecurityEvent.objects.filter(timestamp__gte=since)
        total_events = events_qs.count()
        
        events_by_severity = events_qs.values('severity').annotate(count=Count('id'))
        severity_counts = {item['severity']: item['count'] for item in events_by_severity}
        
        # Agent status
        agent_threshold = timezone.now() - timedelta(minutes=2)
        total_agents = Agent.objects.filter(is_active=True).count()
        online_agents = Agent.objects.filter(
            is_active=True,
            last_heartbeat__gte=agent_threshold
        ).count()
        
        # Alert counts
        alerts_qs = DetectionAlert.objects.filter(triggered_at__gte=since)
        total_alerts = alerts_qs.count()
        new_alerts = alerts_qs.filter(status='NEW').count()
        critical_alerts = alerts_qs.filter(severity='CRITICAL', status='NEW').count()
        
        # Top event IDs
        top_events = events_qs.values('event_id').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        # Top hosts by events
        top_hosts = events_qs.values('hostname').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        # Events per hour (for timeline chart)
        events_timeline = []
        for i in range(hours, -1, -1):
            hour_start = timezone.now() - timedelta(hours=i)
            hour_end = hour_start + timedelta(hours=1)
            count = SecurityEvent.objects.filter(
                timestamp__gte=hour_start,
                timestamp__lt=hour_end
            ).count()
            events_timeline.append({
                'hour': hour_start.isoformat(),
                'count': count
            })
        
        return Response({
            'period_hours': hours,
            'events': {
                'total': total_events,
                'by_severity': severity_counts,
            },
            'agents': {
                'total': total_agents,
                'online': online_agents,
                'offline': total_agents - online_agents,
            },
            'alerts': {
                'total': total_alerts,
                'new': new_alerts,
                'critical': critical_alerts,
            },
            'top_event_ids': list(top_events),
            'top_hosts': list(top_hosts),
            'events_timeline': events_timeline,
        })


class DashboardTimelineView(APIView):
    """Event timeline data for charts"""
    
    def get(self, request):
        hours = int(request.query_params.get('hours', 24))
        
        timeline = []
        for i in range(hours, -1, -1):
            hour_start = timezone.now() - timedelta(hours=i)
            hour_end = hour_start + timedelta(hours=1)
            
            qs = SecurityEvent.objects.filter(
                timestamp__gte=hour_start,
                timestamp__lt=hour_end
            )
            
            timeline.append({
                'timestamp': hour_start.isoformat(),
                'total': qs.count(),
                'critical': qs.filter(severity='CRITICAL').count(),
                'high': qs.filter(severity='HIGH').count(),
                'medium': qs.filter(severity='MEDIUM').count(),
            })
        
        return Response({'timeline': timeline})


# UI Views
def dashboard_home(request):
    """Main dashboard page"""
    return render(request, 'dashboard/home.html')


def events_page(request):
    """Events browser page"""
    return render(request, 'dashboard/events.html')


def alerts_page(request):
    """Alerts page"""
    return render(request, 'dashboard/alerts.html')


def agents_page(request):
    """Agents management page"""
    return render(request, 'dashboard/agents.html')


def query_page(request):
    """PQL Query console page"""
    return render(request, 'dashboard/query.html')


def doc_page(request):
    """Documentation page"""
    return render(request, 'dashboard/doc.html')

