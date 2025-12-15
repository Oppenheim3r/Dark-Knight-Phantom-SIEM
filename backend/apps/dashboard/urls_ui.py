"""
Dark Knight Phantom SIEM - Dashboard UI URLs
"""
from django.urls import path
from django.shortcuts import redirect
from .views import events_page, alerts_page, agents_page, query_page, doc_page

def root_redirect(request):
    """Redirect root to events page"""
    return redirect('/events/')

urlpatterns = [
    path('', root_redirect, name='root'),
    path('events/', events_page, name='events'),
    path('alerts/', alerts_page, name='alerts'),
    path('agents/', agents_page, name='agents'),
    path('query/', query_page, name='query'),
    path('doc/', doc_page, name='doc'),
]

