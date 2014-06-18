""" Helpers to support json encoding of session data """

from datetime import datetime

from session_security.settings import (
    EXPIRE_AFTER_CUSTOM_SESSION_KEY,
    EXPIRE_AFTER,
    WARN_AFTER,
    WARN_BEFORE
)


def set_last_activity(session, dt):
    """ Set the last activity datetime as a string in the session. """
    session['_session_security'] = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')


def get_last_activity(session):
    """
    Get the last activity datetime string from the session and return the
    python datetime object.
    """
    return datetime.strptime(
        session['_session_security'], '%Y-%m-%dT%H:%M:%S.%f')


def get_expire_after(request):
    """
    Calculate EXPIRE_AFTER value while accounting for
    custom/user-defined value
    """

    if EXPIRE_AFTER_CUSTOM_SESSION_KEY is None:
        return EXPIRE_AFTER

    expire_after_value = request.session.get(
        EXPIRE_AFTER_CUSTOM_SESSION_KEY
    )

    if isinstance(expire_after_value, int) and expire_after_value > 0:
        return expire_after_value
    else:
        return EXPIRE_AFTER


def get_warn_after(request):
    """
    Calculate WARN_AFTER value while accounting for case
    where EXPIRE_AFTER may be smaller
    """

    expire_after_value = get_expire_after(request)
    warn_after_value = WARN_AFTER

    if WARN_BEFORE is not None:
        warn_after_value = expire_after_value - WARN_BEFORE

    if (warn_after_value < 0) or \
            (expire_after_value - warn_after_value < 0):
        warn_after_value = 1

    return warn_after_value
