import json
import time
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from camoufox import Camoufox
import requests
from fake_useragent import UserAgent
from tldextract import extract
from detectionattrenum import DetectMode
from playwright.sync_api import sync_playwright
from .dom_detection_result_model import DomDetectionResult
from rule_parser import DomRule
from detectionattrenum import DomDetectionCase
import dom_object_detection.dom_object_detection_function as domdf
import os


SKIPPING_CASE = [
    "phishing",
    "404",
    "503",
    "验证页面",
    "just a moment",
    "attention required",
    "sitenotfound",
    "blognotfound",
    "deployment unavailable",
    "plesk",
    "403",
    "blocked",
    "access denied",
    "captcha",
    "please verify",
    "unusual traffic",
    "deployment unavailable",
    "checking your browser...",
    "vérification de sécurité",
    "honninkakunin",
    "zugriff verweigert",
    "hosting services unavailable",
    "site currently unavailable",
    "this store is unavailable",
    "website expired",
    "coming soon",
    "unknown domain",
    "redirecting...",
    "error: the request could not be satisfied",
    "opensearch dashboards",
]

SKIPPING_CASE = [s.lower().strip().replace(" ", "").replace("\t", "") for s in SKIPPING_CASE]

class DomObjectDetectionHandler:
    def __init__(self, dom_rules: list[DomRule], 
                 ):
        self._dom_rules: list[DomRule] = dom_rules
    
    def run_detection(self, web_rul:str,html:str,score_mode = True):
        dom_risk_score: int = 0
        flagged_rules: list[DomRule] = []
        external_links:list[str] = []
        error_flag = False
        soup = BeautifulSoup(html, "html.parser")
            
        

        for dom_rule in self._dom_rules:
            detect_case_len = len(dom_rule.detect_case)
            flagged_case_in_rules = 0
            accumulative_score = 0
            
            for detect_case in dom_rule.detect_case:
                    match detect_case:
                        
                        
                        case DomDetectionCase.FORM_ACTION_MAILTO:
                            
                            r = domdf.check_mailto_form(
                                soup,dom_rule)
                            if r:
                                flagged_case_in_rules += 1
                               
                                  
                        case DomDetectionCase.MULTIPLE_SUBMIT:
                            
                            r = domdf.check_multiple_submit(
                                 soup,dom_rule.multiple_submit_detection_yparam)

                            if r:
                                flagged_case_in_rules += 1
                        
                        # case DomDetectionCase.PHISHING_EXTERNAL_LINK_CHECK:
                        #     phishing_keyword = dom_rule.phishing_signal_external_link_check["phishing_keywords"]
                        #     tag = dom_rule.phishing_signal_external_link_check["tag"]
                        #     max_text_length = dom_rule.phishing_signal_external_link_check["max_text_length"]
                        #     r = domdf.phishing_redirect_scam(web_rul,soup,tag,phishing_keyword,max_text_length)
                            
                        #     if r:
                        #         flagged_case_in_rules += 1

                            
                        case DomDetectionCase.CHECK_PAGE_SIGNALS:

                            r =  domdf.check_missing_legitimacy_signals(soup,dom_rule.check_missing_legitimacy_signals_yparam)
                            if r :
                                flagged_case_in_rules += 1
                                
                        case DomDetectionCase.OBFUSCATION_JAVASCRIPT:
                            
                            re_list = dom_rule.obfuscation_js_detect_yparam["regex_list"]
                            r = domdf.check_obfuscated_js(html,re_list)
                            
                            if r:
                                flagged_case_in_rules += 1
                        
                    
                        case DomDetectionCase.BODY_TEXT_TAG_COUNT:
                            body_length_minium = dom_rule.body_text_tag_count_yparam["body_length_minimum"]
                            tag_count_minimum = dom_rule.body_text_tag_count_yparam["tag_minimum"]
                            
                            r = domdf.body_tag_count(soup,body_length_minium,tag_count_minimum)
                            
                            if r:
                                flagged_case_in_rules += 1
                            
                        # case DomDetectionCase.MIMIC_LOGIN_STRUCTURE:
                        #     mimic_login_structure_setting =  dom_rule.mimic_login_site_structure_yparam
                        #     similarity_theresold = mimic_login_structure_setting["similarity_theresold"]
                        #     structure_list = mimic_login_structure_setting["structure_list"]
                            
                        #     r = domdf.is_login_structure_mimic(soup,web_rul,structure_list,similarity_theresold)
                            
                        #     if r:
                        #         flagged_case_in_rules += 1
                             
                        case DomDetectionCase.PAGE_TITLE_MATCHING:
                          
                            generic_title = dom_rule.page_domain_matching_yparam["generic_titles"]
                            min_len = dom_rule.page_domain_matching_yparam["min_domain_len"]
                            deficient = dom_rule.page_domain_matching_yparam["min_similarity_score"]
                            meta_list = dom_rule.page_domain_matching_yparam["detect_meta"]
                            title_acronym_detection = dom_rule.page_domain_matching_yparam["title_acronym_detection"]
                            
                            r = domdf.check_page_title_mismatch(soup,web_rul,min_len,generic_title,meta_list,title_acronym_detection,deficient)
                            if r:
                                flagged_case_in_rules += 1
                        
                        case DomDetectionCase.TECHNOLOGIES_COUNT:
                            tech_list = dom_rule.techologies_yparam["tech_list"]
                            min_appear = dom_rule.techologies_yparam["min_appear"]
                            
                            r = domdf.count_detected_technologies(soup,tech_list,min_appear)
                            if r:
                                flagged_case_in_rules += 1
                            
                            
            if detect_case_len == flagged_case_in_rules and detect_case_len > 0:
                flagged_rules.append(dom_rule)
                if score_mode :
                    dom_risk_score += accumulative_score
                    dom_risk_score += dom_rule.risk_score
                    
        return DomDetectionResult(web_url=web_rul,
                                  risk_score=dom_risk_score,
                                  flagged_rules=flagged_rules,
                                  external_links=external_links,
                                  error_flag=error_flag
                                  )
