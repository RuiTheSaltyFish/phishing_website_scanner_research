

from detectionattrenum import DomainDetectionCase
from .base_rule_template import BaseRuleTemplate

class DomainRule(BaseRuleTemplate):
    def __init__(self,
                 title: str,
                 description: str,
                 date: str,
                 dtype: str,
                 detection: dict,
                 risk_score: int = 0,
                 ):  # Add new variable
        super().__init__(title, description, date, dtype, detection, risk_score)
        self.domain_age_below_month_yparam = None
        self.domain_age_group = None
        self.detect_case = []
        self.dns_name_server_check_yparam = None
        self.page_rank_yparam = None
        self.dns_record_check_yparam = None
        self.domain_registration_period_year_yparam = None
        self.parse_domain_rule_feature()

    @classmethod
    def from_detection_rule(cls, rule: BaseRuleTemplate):
        """Promote a DetectionRule to a UrlRule"""
        return cls(
            title=rule.title,
            description=rule.description,
            date=rule.date,
            dtype=rule.dtype,
            detection=rule.detection,
            risk_score=rule.risk_score
        )

    def __repr__(self):
        return (f"{self.__class__.__name__}("
                f"title='{self.title}', "
                f"description='{self.description}', "
                f"date='{self.date}', "
                f"dtype='{self.dtype}', "
                f"detection={self.detection}, "
                f"risk_score='{self.risk_score}', "
                f"domain_age_below_month={self.domain_age_below_month_yparam}, "
                f"detect_case={self.detect_case})")


    def parse_domain_rule_feature(self):
        detection = self.detection
                    
        if "ssl_verify" in detection:
            self.ssl_verify = detection["ssl_verify"]
            self.detect_case.append(DomainDetectionCase.SSL_CHECK)
         
        if 'domain_age_below_by_month' in detection:
            self.domain_age_below_month_yparam = detection['domain_age_below_by_month']
            self.detect_case.append(DomainDetectionCase.DOMAIN_AGE)
        
        if "page_rank" in detection:
            self.page_rank_yparam = detection["page_rank"]
            self.detect_case.append(DomainDetectionCase.PAGERANK)
    
        if "dns_name_server_check" in detection:
            self.dns_name_server_check_yparam = detection["dns_name_server_check"]
            self.detect_case.append(DomainDetectionCase.DNS_NAME_SERVER_CHECK)

        if "domain_registration_period_year" in detection:
            self.domain_registration_period_year_yparam = detection["domain_registration_period_year"]
            self.detect_case.append(DomainDetectionCase.DOMAIN_REGISTER_YEAR)
        
        if "dns_record_check" in detection:
            self.dns_record_check_yparam = detection["dns_record_check"]
            self.detect_case.append(DomainDetectionCase.DNS_RECORD_CHECK)

        if 'min_redirect' in detection:
            self.min_redirect_yparam = detection['min_redirect']
            self.detect_case.append(DomainDetectionCase.MIN_RIDIRECT)
        
        if "redirect_extra" in detection:
            self.redirect_extra_yparam = detection["camouflage_redirect"]
            self.detect_case.append(DomainDetectionCase.REDIRECT_RANK)