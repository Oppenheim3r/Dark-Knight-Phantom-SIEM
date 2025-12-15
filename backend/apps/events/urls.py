"""
Dark Knight Phantom SIEM - Event URLs
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    SecurityEventViewSet,
    EventSourceViewSet,
    EventCategoryViewSet,
    EventIngestView,
    SingleEventIngestView,
)

router = DefaultRouter()
router.register(r'list', SecurityEventViewSet, basename='events')
router.register(r'sources', EventSourceViewSet, basename='event-sources')
router.register(r'categories', EventCategoryViewSet, basename='event-categories')

urlpatterns = [
    # Ingestion endpoints (used by agents)
    path('ingest/', EventIngestView.as_view(), name='event-ingest'),
    path('ingest/single/', SingleEventIngestView.as_view(), name='event-ingest-single'),
    
    # ViewSet routes
    path('', include(router.urls)),
]



