import logging
from rule_parser import UrlRule


import url_detection.url_detection_function as urdf
from detectionattrenum import UrlDetectionCase
from .url_detection_result_model import UrlDetectionResult


logging.basicConfig(level=logging.INFO)


class UrlDetectionHandler:
    def __init__(self, url_rules: list[UrlRule]):
        self.url_rules = url_rules

    def run_detection(self, web_rul: str,final_url:str,score_mode = True):
        risk_score:int = 0
        flagged_rules:list[UrlRule] = []
        for url_rule in self.url_rules:
            detect_case_len = len(url_rule.detect_case)
            flagged_case_in_rules = 0
            accumulative_risk_score = 0
  
            for detect_case in url_rule.detect_case:
                match detect_case:
                    case UrlDetectionCase.URL_REGEX:
                        url = final_url if final_url else web_rul
                        detect_result = urdf.detect_url_regex(
                            url_rule, url)
                        if detect_result:
                            if "limit_occurrences" in url_rule.url_regex_yparam:
                               if len(detect_result) > url_rule.url_regex_yparam["limit_occurrences"]:
                                   flagged_case_in_rules += 1
                                
                            elif "accumulative" in url_rule.url_regex_yparam:
                                   
                                   flagged_case_in_rules += 1
                                  
                                   if score_mode:
                                        accumulative = url_rule.url_regex_yparam["accumulative"]
                                        if accumulative:
                                            accumulative_risk_score += len(detect_result) * url_rule.risk_score
                                        else:
                                            accumulative_risk_score += url_rule.risk_score

                            else:
                                flagged_case_in_rules += 1
                    
                    
                    case UrlDetectionCase.URLSHORTENERS:
                        
                        r = urdf.is_url_shortener(web_rul,final_url,url_rule.url_shorteners_detection_yparam)
                        if r:
                            flagged_case_in_rules += 1
                                                  
                    case UrlDetectionCase.SUB_DOMAIN_LEVEL:
                        url = final_url if final_url else web_rul
                        detect_result = urdf.detect_web_url_subdomain_level(
                            url_rule, url)
                        if detect_result:
                            flagged_case_in_rules += 1
                       
                            
                    case UrlDetectionCase.OVER_LENGTH:
                        url = final_url if final_url else web_rul
                        detect_result = urdf.detect_web_url_length(
                            url_rule, url)
                        if detect_result:
                            flagged_case_in_rules += 1

                    case UrlDetectionCase.HTTPS_CHECK:
                        url = final_url if final_url else web_rul
                        detect_result = urdf.is_https(url)
                        if not detect_result:
                            flagged_case_in_rules += 1
                    
                    case UrlDetectionCase.DOMAIN_NAME_ENTROPY:
                        url = final_url if final_url else web_rul
                        threshold = url_rule.gribberish_domain_name_yparam["threshold"]
                        min_length = url_rule.gribberish_domain_name_yparam["min_length"]
                        detect_result = urdf.calculate_domain_name_entrophy(url,min_length,threshold)
                        if detect_result:
                             flagged_case_in_rules += 1

                    case UrlDetectionCase.HOSTING_PLATFORM_PENALTY_SCORE:
                        url = final_url if final_url else web_rul
                        platform_list = url_rule.hosting_platform_penalty_score_yparam["platform_list"]
                        platform_domain_lists = [item["domain"] for item in platform_list]
                        detect_result = urdf.detect_hosting_platform_url(url,web_rul,platform_domain_lists)
                        if detect_result:
                             flagged_case_in_rules += 1
                             
                    # case UrlDetectionCase.TYPOSQUATTING:
                    #     target_domain = url_rule.typosquatting["target_domain"] 
                    #     homoglyph_map = url_rule.typosquatting["homoglyph_map"]
                    #     digit_substitution = url_rule.typosquatting["digit_substitution"]
                    #     detect_result = urdf.is_typosquatting(web_rul,target_domain,digit_substitution,homoglyph_map)
                        
                    #     if detect_result:
                    #         flagged_case_in_rules += 1

        
            if detect_case_len == flagged_case_in_rules and detect_case_len > 0:
                flagged_rules.append(url_rule)
                if score_mode:
                    risk_score += url_rule.risk_score
        
        
        return UrlDetectionResult(web_url=web_rul,risk_score=risk_score,flagged_rules=flagged_rules)             

