"""
ASGI config for Dark Knight Phantom SIEM.
Supports WebSocket for real-time dashboard updates.
"""
import os
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dark_knight_phantom.settings')
application = get_asgi_application()



