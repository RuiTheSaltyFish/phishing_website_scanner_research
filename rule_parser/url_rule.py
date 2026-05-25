from detectionattrenum import UrlDetectionCase
from .base_rule_template import BaseRuleTemplate



class UrlRule(BaseRuleTemplate):
    def __init__(self,
                 title: str,
                 description: str,
                 date: str,
                 dtype: str,
                 detection: dict,
                 risk_score: int = 0,
                 ):  # Add new variable
        super().__init__(title, description, date, dtype, detection, risk_score)
        self.url_regex_yparam = None
        self.sub_domain_level_yparam = None
        self.url_length_yparam = None
        self.detect_case = []
        self.domain_name_only_yparam = False
        self.https_check_yparam = False
        self.gribberish_domain_name_yparam = None
        self.typosquatting = None
        self.hosting_platform_penalty_score_yparam = None
        self.parse_url_rule_feature()

    @classmethod
    def from_detection_rule(cls, rule: BaseRuleTemplate):
        """Promote a DetectionRule to a UrlRule"""
        return cls(
            title=rule.title,
            description=rule.description,
            date=rule.date,
            dtype=rule.dtype,
            detection=rule.detection,
            risk_score=rule.risk_score,
            
        )
    

    def __repr__(self):
        return (f"{self.__class__.__name__}("
                f"title='{self.title}', "
                f"description='{self.description}', "
                f"date='{self.date}', "
                f"dtype='{self.dtype}', "
                f"detection={self.detection}, "
                f"risk_score='{self.risk_score}', "
                f"url_regex={self.url_regex_yparam}, "
                f"sub_domain_level={self.sub_domain_level_yparam}, "
                f"domain_name_only={self.domain_name_only_yparam},"
                f"over_length={self.url_length_yparam})")

    
    def parse_url_rule_feature(self):
        detection = self.detection
        if 'url_regex' in detection:
            self.url_regex_yparam = detection['url_regex']
            self.detect_case.append(UrlDetectionCase.URL_REGEX)
        
        if 'sub_domain_level' in detection:
            self.sub_domain_level_yparam = detection['sub_domain_level']
            self.detect_case.append(UrlDetectionCase.SUB_DOMAIN_LEVEL)
            
        if "gibberish_domain_name" in detection:
            self.gribberish_domain_name_yparam = detection["domain_name_entropy_threshold"]
            self.detect_case.append(UrlDetectionCase.FUZZ_GIBBERISH)

        if 'length_detection' in detection:
            self.url_length_yparam = detection["length_detection"]
            self.detect_case.append(UrlDetectionCase.OVER_LENGTH)
            
        if "domain_name_only" in detection:
            self.domain_name_only_yparam = detection["domain_name_only"]
        
        if "https_check" in detection:
            self.https_check_yparam = detection["https_check"]
            self.detect_case.append(UrlDetectionCase.HTTPS_CHECK)
            
        if "hosting_platform_penalty_score" in detection:
            self.hosting_platform_penalty_score_yparam = detection["hosting_platform_penalty_score"]
            self.detect_case.append(UrlDetectionCase.HOSTING_PLATFORM_PENALTY_SCORE)
        
        if "url_shorteners" in detection:
            self.url_shorteners_detection_yparam = detection["url_shorteners"]
            self.detect_case.append(UrlDetectionCase.URLSHORTENERS)
        
        # if "typosquatting" in detection:
        #     self.typosquatting = detection["typosquatting"]
        #     self.detect_case.append(UrlDetectionCase.TYPOSQUATTING)
            
    


