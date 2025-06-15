from django.contrib.auth import logout
from django.contrib import messages
from django.conf import settings
from django.shortcuts import redirect
from academia.models import MIITRole, MIITUserRole, UserDevice
from django.contrib.sessions.models import Session
from ua_parser import user_agent_parser
from django.utils import timezone
from datetime import timedelta

class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            role = request.session.get('selected_role')
            timeout = settings.ROLE_SESSION_TIMEOUT.get(role, settings.SESSION_COOKIE_AGE)

            if request.session.get_expire_at_browser_close():
                # Session will expire when the browser is closed
                pass

            # Set the selected_role in the session
            user_roles = MIITRole.objects.filter(RoleID__in=MIITUserRole.objects.filter(UserID=request.user.UserID).values_list('RoleID', flat=True))
            if user_roles:
                request.session['user_roles'] = [role.RoleID for role in user_roles]
                if role:
                    request.session['selected_role'] = role

            # Set the session expiry time based on the role
            # Check if the session is new or not
            if request.session.session_key is None:
                # This is a new session, set the expiry time to the default value
                request.session.set_expiry(settings.SESSION_COOKIE_AGE)

            else:
                # This is an existing session, set the expiry time based on the role
                request.session.set_expiry(timeout)

        elif 'login' in request.path:
                # Session has expired based on the timeout value
                logout(request)
                messages.warning(request, 'Your session has expired. Please log in again.', extra_tags='session_expired')
                return redirect('login')

        response = self.get_response(request)
        return response



class DeviceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.user.is_authenticated:
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            ip_address = self.get_client_ip(request)

            # Parse the user agent to get the device, browser, and OS information
            agent = user_agent_parser.Parse(user_agent)
            device_name = agent.get('device', {}).get('family', 'Unknown')
            browser = agent.get('user_agent', {}).get('family', 'Unknown')
            os = agent.get('os', {}).get('family', 'Unknown')

            # Get session key
            session_key = request.session.session_key

            # Update or create the UserDevice entry
            UserDevice.objects.update_or_create(
                user=request.user,
                session_key=session_key,
                defaults={
                    'device_name': device_name,
                    'ip_address': ip_address,
                    'browser': browser,
                    'os': os,
                    'last_activity': timezone.now(),
                }
            )

            # Remove expired sessions
            session_duration = timedelta(minutes=settings.SESSION_COOKIE_AGE // 60)
            now = timezone.now()
            expired_sessions = UserDevice.objects.filter(last_activity__lt=now - session_duration)
            expired_sessions.delete()

        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
