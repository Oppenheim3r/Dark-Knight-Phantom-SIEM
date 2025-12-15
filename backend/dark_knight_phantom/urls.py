"""
Dark Knight Phantom SIEM - URL Configuration
"""
from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse


def api_root(request):
    """API Root endpoint"""
    return JsonResponse({
        'name': 'Dark Knight Phantom SIEM',
        'version': '1.0.0',
        'endpoints': {
            'events': '/api/v1/events/',
            'agents': '/api/v1/agents/',
            'alerts': '/api/v1/alerts/',
            'query': '/api/v1/query/',
            'dashboard': '/api/v1/dashboard/',
            'detection': '/api/v1/detection/',
        }
    })


urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),
    
    # API Root
    path('api/', api_root, name='api-root'),
    path('api/v1/', api_root, name='api-v1-root'),
    
    # API Endpoints
    path('api/v1/events/', include('apps.events.urls')),
    path('api/v1/agents/', include('apps.agents.urls')),
    path('api/v1/alerts/', include('apps.alerts.urls')),
    path('api/v1/query/', include('apps.query.urls')),
    path('api/v1/dashboard/', include('apps.dashboard.urls')),
    path('api/v1/detection/', include('apps.detection.urls')),
    
    # Dashboard UI
    path('', include('apps.dashboard.urls_ui')),
]

