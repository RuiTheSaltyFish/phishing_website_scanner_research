from enum import Enum


class DomainDetectionError(Enum):
    REQUEST_ERROR = 1,
    SSL_CERTIFICATE_ERROR = 2,
    CONNECTION_ERROR = 3,
    TIME_OUT_ERROR = 4,
    DOMAIN_NOT_FOUND = 5
