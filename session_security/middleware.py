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

    def is_session_expired(self, request, current_time, last_activity_time):
        """ Decide is session expired or not. If you want to extend this
        middleware's logic you can subclass from it and implement this method.
        """
        last_activity_delta = current_time - last_activity_time
        max_expire_delta = timedelta(seconds=get_expire_after(request))
        return last_activity_delta >= max_expire_delta

    def process_request(self, request):
        """ Update last activity time or logout. """
        if not request.user.is_authenticated():
            return

        now = datetime.now()
        self.update_last_activity(request, now)

        last_activity = get_last_activity(request.session)

        if self.is_session_expired(request, now, last_activity):
            logout(request)
        elif request.path not in PASSIVE_URLS:
            set_last_activity(request.session, now)

    def update_last_activity(self, request, now):
        """
        If ``request.GET['idleFor']`` is set, check if it refers to a more
        recent activity than ``request.session['_session_security']`` and
        update it in this case.
        """
        if '_session_security' not in request.session:
            set_last_activity(request.session, now)

        last_activity = get_last_activity(request.session)
        server_idle_for = (now - last_activity).seconds

        if (request.path == reverse('session_security_ping') and
                'idleFor' in request.GET):
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
                last_activity = now - timedelta(seconds=client_idle_for)

                # Update the session
                set_last_activity(request.session, last_activity)
