from dataclasses import dataclass

from rule_parser import UrlRule

@dataclass(frozen=True)
class UrlDetectionResult:
    web_url:str
    risk_score:int
    flagged_rules:list[UrlRule]