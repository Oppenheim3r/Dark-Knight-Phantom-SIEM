"""
Dark Knight Phantom SIEM - Dashboard API URLs
"""
from django.urls import path
from .views import DashboardStatsView, DashboardTimelineView

urlpatterns = [
    path('stats/', DashboardStatsView.as_view(), name='dashboard-stats'),
    path('timeline/', DashboardTimelineView.as_view(), name='dashboard-timeline'),
]



