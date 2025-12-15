"""
Dark Knight Phantom SIEM - Agent URLs
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    AgentViewSet,
    AgentRegistrationView,
    AgentHeartbeatView,
    AgentLogChannelViewSet,
    AgentCommandViewSet,
)

router = DefaultRouter()
router.register(r'list', AgentViewSet, basename='agents')
router.register(r'channels', AgentLogChannelViewSet, basename='log-channels')
router.register(r'commands', AgentCommandViewSet, basename='agent-commands')

urlpatterns = [
    # Agent registration and heartbeat
    path('register/', AgentRegistrationView.as_view(), name='agent-register'),
    path('heartbeat/', AgentHeartbeatView.as_view(), name='agent-heartbeat'),
    
    # ViewSet routes
    path('', include(router.urls)),
]



