from dataclasses import dataclass


from rule_parser import DomRule



@dataclass(frozen=True)
class DomDetectionResult:
    web_url: str
    risk_score: int
    flagged_rules: list[DomRule]
    external_links : list[str]
    error_flag: bool
