from dataclasses import dataclass

from rule_parser import DomainRule

@dataclass(frozen=True)
class DomainDetectionResult:
    web_url:str
    risk_score:int
    flagged_rules:list[DomainRule]
    error:list[str]