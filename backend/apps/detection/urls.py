"""
Dark Knight Phantom SIEM - Detection URLs
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    DetectionRuleViewSet, DetectionAlertViewSet,
    AlertSuppressionViewSet, EntityTrackerViewSet,
    DetectionTestView
)

router = DefaultRouter()
router.register(r'rules', DetectionRuleViewSet, basename='detection-rules')
router.register(r'alerts', DetectionAlertViewSet, basename='detection-alerts')
router.register(r'suppressions', AlertSuppressionViewSet, basename='alert-suppressions')
router.register(r'trackers', EntityTrackerViewSet, basename='entity-trackers')

urlpatterns = [
    path('', include(router.urls)),
    path('test/', DetectionTestView.as_view(), name='detection-test'),
]



