import logging
import requests
from dom_object_detection import DomObjectDetectionHandler
from domain_detection import DomainDetectionHandler
from rule_parser import DomRule
from rule_parser import DomainRule
from rule_parser import UrlRule
from url_detection import UrlDetectionHandler


def check_external_link_resource(external_list: list[str],
                                 url_rules: list[UrlRule],
                                 dom_rules: list[DomRule],
                                 domains_rule: list[DomainRule],
                                 response_body:str,
                                 web_url: str) -> dict:

    ddh = DomainDetectionHandler(
        domain_rules=domains_rule, url_rules=url_rules, dom_rules=dom_rules)
    urldh = UrlDetectionHandler(url_rules=url_rules)
    domdh = DomObjectDetectionHandler(
        omain_rules=domains_rule, url_rules=url_rules, 
        dom_rules=dom_rules,
        )

    
    external_check_result_dict = {}

    for url in external_list:
        total_risk_score = 0
        ddhr = ddh.run_detection(url)
        urldr = urldh.run_detection(url)
        domdr = domdh.run_detection(url,response_body,external_link_check_flag=False)

        total_risk_score += ddhr.risk_score
        total_risk_score += urldr.risk_score
        total_risk_score += domdr.risk_score

        external_check_result_dict[url] = {"domain_result":ddhr}
        external_check_result_dict[url] = {"url_result":ddhr}
        external_check_result_dict[url] = {"dom_result":ddhr}
        external_check_result_dict[url] = {"total_risk_score":total_risk_score}
        

    return external_check_result_dict


def detect_check_final_destination(check_case: list[str],
                                   url_rules: list[UrlRule],
                                   dom_rules: list[DomRule],
                                   domains_rule: list[DomainRule],
                                   web_url: str) -> any:
    try:
        # Send a GET request with `allow_redirects=True` (default)
        response = requests.get(web_url, allow_redirects=True)
        risk_score = 0
        redirect_destination_result_dict = {}
        # Check if there are any redirects
        if response.history:
            final_destination = response.url
            for cc in check_case:
                match cc:
                    case "domain":
                        ddh = DomainDetectionHandler(domain_rules=domains_rule)
                        ddhr = ddh.run_detection(final_destination)
                        redirect_destination_result_dict["domain"] = ddhr
                        risk_score += ddhr.risk_score

                    case "url":
                        urldh = UrlDetectionHandler(url_rules=url_rules)
                        urldhr = urldh.run_detection(final_destination)
                        redirect_destination_result_dict["url"] = urldhr
                        risk_score += urldhr.risk_score
                        
                    case "dom":
                        domdh = DomObjectDetectionHandler(dom_rules=dom_rules)
                        domdhr = domdh.run_detection(
                            web_url, response_body=response.text)
                        risk_score += domdhr.risk_score
            
        return risk_score
                        

    except requests.exceptions.RequestException as e:
        logging.error(f"detect_check_final_destination():{e}")
        return False