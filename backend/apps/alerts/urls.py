"""
Dark Knight Phantom SIEM - Alert URLs
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AlertViewSet, AlertCommentViewSet

router = DefaultRouter()
router.register(r'list', AlertViewSet, basename='alerts')
router.register(r'comments', AlertCommentViewSet, basename='alert-comments')

urlpatterns = [
    path('', include(router.urls)),
]



