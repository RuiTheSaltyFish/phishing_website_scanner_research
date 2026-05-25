from enum import Enum


class DomainDetectionCase(Enum):
    DOMAIN_AGE = 1,
    SSL_CHECK = 2,
    DNS_RECORD_CHECK = 4,
    PAGERANK = 5,
    DNS_NAME_SERVER_CHECK = 6,
    DOMAIN_REGISTER_YEAR = 7,
    MIN_RIDIRECT = 8,
    REDIRECT_RANK= 9
    
    