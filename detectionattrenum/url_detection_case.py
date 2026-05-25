from enum import Enum


class UrlDetectionCase(Enum):
    URL_REGEX = 1,
    SUB_DOMAIN_LEVEL = 2,
    OVER_LENGTH = 3,
    HTTPS_CHECK = 4,
    SHORTENING_SERVICE = 5,
    FUZZ_GIBBERISH = 6,
    HOSTING_PLATFORM_PENALTY_SCORE = 7,
    TYPOSQUATTING = 8,
    URLSHORTENERS = 9,
