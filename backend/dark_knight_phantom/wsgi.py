"""
WSGI config for Dark Knight Phantom SIEM.
"""
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dark_knight_phantom.settings')
application = get_wsgi_application()



