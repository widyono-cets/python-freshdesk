from requests import HTTPError


class FreshserviceError(HTTPError):
    """
    Base error class.

    Subclassing HTTPError to avoid breaking existing code that expects only HTTPErrors.
    """


class FreshserviceBadRequest(FreshserviceError):
    """Most 40X and 501 status codes"""


class FreshserviceUnauthorized(FreshserviceError):
    """401 Unauthorized"""


class FreshserviceAccessDenied(FreshserviceError):
    """403 Forbidden"""


class FreshserviceNotFound(FreshserviceError):
    """404"""


class FreshserviceRateLimited(FreshserviceError):
    """429 Rate Limit Reached"""


class FreshserviceServerError(FreshserviceError):
    """50X errors"""
