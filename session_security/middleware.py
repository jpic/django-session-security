"""
SessionSecurityMiddleware is the heart of the security that this application
attemps to provide.

To install this middleware, add to your ``settings.MIDDLEWARE_CLASSES``::

    'session_security.middleware.SessionSecurityMiddleware'

Make sure that it is placed **after** authentication middlewares.
"""
from datetime import datetime, timedelta

from django.contrib.auth import logout
from django.core.urlresolvers import reverse

from .utils import get_last_activity, set_last_activity, get_expire_after
from .settings import PASSIVE_URLS


class SessionSecurityMiddleware(object):
    """
    In charge of maintaining the real 'last activity' time, and log out the
    user if appropriate.
    """
    ping_url = reverse('session_security_ping')

    def is_ping_request(self, request):
        """ Determine should request be processed in ping request handler """
        return request.path == self.ping_url and 'idleFor' in request.GET

    def is_session_expired(self, request, current_time, last_activity_time):
        """ Decide is session expired or not. By subclassing from middleware
        you can implement your logic here"""
        last_activity_delta = current_time - last_activity_time
        max_expire_delta = timedelta(seconds=get_expire_after(request))
        return last_activity_delta >= max_expire_delta

    def needs_activity_update(self, request, current_time, last_activity_time):
        """ Decide should last activity time be updated or not. Reimplement
         this method in middleware subclass for your logic"""
        return request.path not in PASSIVE_URLS

    def process_request(self, request):
        """ Update last activity time or logout. """
        if not request.user.is_authenticated():
            return

        now = datetime.now()

        # Check if request got session expire set
        if '_session_security' not in request.session:
            set_last_activity(request.session, now)
            # No need to check newly added value. Exiting...
            return

        # Ping requests got special handling functions
        if self.is_ping_request(request):
            self.handle_ping_request(request, now)

        last_activity = get_last_activity(request.session)

        if self.is_session_expired(request, now, last_activity):
            logout(request)
        elif self.needs_activity_update(request, now, last_activity):
            set_last_activity(request.session, now)

    def handle_ping_request(self, request, current_time):
        """
        If ``request.GET['idleFor']`` is set, check if it refers to a more
        recent activity than ``request.session['_session_security']`` and
        update it in this case.
        """
        last_activity = get_last_activity(request.session)
        server_idle_for = (current_time - last_activity).seconds

        # Gracefully ignore non-integer values
        try:
            client_idle_for = int(request.GET['idleFor'])
        except ValueError:
            return

        # Disallow negative values, causes problems with delta calculation
        if client_idle_for < 0:
            client_idle_for = 0

        if client_idle_for < server_idle_for:
            # Client has more recent activity than we have in the session
            last_activity = current_time - \
                            timedelta(seconds=client_idle_for)

            # Update the session
            set_last_activity(request.session, last_activity)
