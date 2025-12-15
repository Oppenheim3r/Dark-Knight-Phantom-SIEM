"""
Dark Knight Phantom SIEM - Query URLs
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PQLExecuteView, SavedQueryViewSet, QueryHistoryViewSet

router = DefaultRouter()
router.register(r'saved', SavedQueryViewSet, basename='saved-queries')
router.register(r'history', QueryHistoryViewSet, basename='query-history')

urlpatterns = [
    path('execute/', PQLExecuteView.as_view(), name='pql-execute'),
    path('', include(router.urls)),
]



