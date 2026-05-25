

from .base_rule_template import BaseRuleTemplate
from detectionattrenum import DomDetectionCase

class DomRule(BaseRuleTemplate):
    def __init__(self,
                 title: str,
                 description: str,
                 date: str,
                 dtype: str,
                 detection: dict,
                 risk_score: int = 0,
                 ):  # Add new variable
        super().__init__(title, description, date, dtype, detection, risk_score)
        self.form_yparam = None
        self.detect_risk_tag_yparam = None
        self.page_domain_matching_yparam = None
        self.detect_case = []
        self.phishing_signal_external_link_check = None
        self.mimic_login_site_yparam = None
        self.obfuscation_js_detect_yparam = None
        self.mimic_login_site_yparam = None
        self.mimic_login_site_structure_yparam = None
        self.parse_dom_rule_feature()
        

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
                f"from={self.form_yparam}, "
                f"forbidden_tag={self.detect_risk_tag_yparam}, "
                f"fuzzy_title={self.page_domain_matching_yparam}"
                )

    def parse_dom_rule_feature(self):
        detection = self.detection
    
        if 'form' in detection:
            self.form_yparam = detection['form']
            if "mailto_detect" in self.form_yparam:
                self.detect_case.append(DomDetectionCase.FORM_ACTION_MAILTO)
            if "detect_cross_domain_submit" in self.form_yparam:
                self.detect_case.append(DomDetectionCase.FORM_ACTION_CROSS_DOMAIN)
        
        if "phishing_signal_external_link_check" in detection:
            self.phishing_signal_external_link_check = detection["phishing_signal_external_link_check"]
            self.detect_case.append(DomDetectionCase.PHISHING_EXTERNAL_LINK_CHECK)
        
    
        if 'detect_risk_tag' in detection:
            self.detect_risk_tag_yparam = detection['detect_risk_tag']
            self.detect_case.append(DomDetectionCase.HIGH_RISK_TAG)
            
        if "page_domain_matching" in detection:
            self.page_domain_matching_yparam = detection["page_domain_matching"]
            self.detect_case.append(DomDetectionCase.PAGE_TITLE_MATCHING)
            
        if "mimic_login_settings" in detection:
            self.mimic_login_site_yparam = detection["mimic_login_settings"]
            self.detect_case.append(DomDetectionCase.MIMIC_LOGIN_SITE)
        
        if "check_missing_legitimacy_signals" in detection:
            self.check_missing_legitimacy_signals_yparam = detection["check_missing_legitimacy_signals"]
            self.detect_case.append(DomDetectionCase.CHECK_PAGE_SIGNALS)
        
        if "multiple_submit_detection" in detection:
            self.multiple_submit_detection_yparam = detection["multiple_submit_detection"]
            self.detect_case.append(DomDetectionCase.MULTIPLE_SUBMIT)
        
        if "mimic_login_structure_settings" in detection:
            self.mimic_login_site_structure_yparam = detection["mimic_login_structure_settings"]
            self.detect_case.append(DomDetectionCase.MIMIC_LOGIN_STRUCTURE)
        
        if "obfuscation_js_detect" in detection:
            self.obfuscation_js_detect_yparam = detection["obfuscation_js_detect"]
            self.detect_case.append(DomDetectionCase.OBFUSCATION_JAVASCRIPT)
        
        if "body_text_tag_count" in detection:
            self.body_text_tag_count_yparam = detection["body_text_tag_count"]
            self.detect_case.append(DomDetectionCase.BODY_TEXT_TAG_COUNT)
        
        if "technologies_count" in detection:
            self.techologies_yparam = detection["technologies_count"]
            self.detect_case.append(DomDetectionCase.TECHNOLOGIES_COUNT)