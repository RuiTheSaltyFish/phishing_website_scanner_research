import requests
from detectionattrenum import DomainDetectionError
from rule_parser import DomainRule
from detectionattrenum import DomainDetectionCase
from domain_detection import domain_detection_function as ddf
from .domain_detection_result_model import DomainDetectionResult
import os


_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_CSV_PATH = os.path.join(_BASE_DIR, "open_rank_score10m.csv")

# _PAGERANK_DB = ddf.load_pagerank(_CSV_PATH)


class DomainDetectionHandler:
    def __init__(self, domain_rules: list[DomainRule]):
        self._domain_rules = domain_rules

    def run_detection(
        self,
        web_url: str,
        redirect_counter: int,
        final_url: str,
        score_mode=True,
    ):
        flagged_rules: list[DomainRule] = []
        domain_risk_score = 0
        error: list[DomainDetectionError] = []

        for domain_rule in self._domain_rules:
            detect_case_len = len(domain_rule.detect_case)
            flagged_case_in_rules = 0

            for detect_case in domain_rule.detect_case:
                match detect_case:
                    # case DomainDetectionCase.PAGERANK:
                    #     if final_url != "":
                    #         detect_url = final_url
                           
                    #     else:
                    #         detect_url = web_url
                        
                    #     if domain_rule.page_rank_yparam["use_build_in_pagerank"]:
                    #         result = ddf.get_pagerank(detect_url,_PAGERANK_DB)
                    #     else:
                    #         result = ddf.get_page_rank_by_api(domain_rule,detect_url)
                        
                    #     deficient_score = float(
                    #         domain_rule.page_rank_yparam["deficient"]
                    #     )

                    #     if result < deficient_score:
                    #         flagged_case_in_rules += 1

                    case DomainDetectionCase.DOMAIN_AGE:
                        if final_url != "":
                            detect_url = final_url
                        else:
                             detect_url = web_url
                        result = ddf.check_domain_age(domain_rule, final_url)
                        if result:
                            flagged_case_in_rules += 1

                    case DomainDetectionCase.SSL_CHECK:
                        ssl_verify_settings = domain_rule.ssl_verify
                        timeout = ssl_verify_settings["timeout"]
                        port = ssl_verify_settings["port"]
                        cert_none_mode = ssl_verify_settings["cert_none_mode"]

                        if final_url != "":
                            result = ddf.suspicious_ssl_cert(
                                final_url, cert_none_mode, timeout, port
                            )
                        else:
                            result = ddf.suspicious_ssl_cert(
                                web_url, cert_none_mode, timeout, port
                            )
                        if result:
                            flagged_case_in_rules += 1


                    case DomainDetectionCase.MIN_RIDIRECT:
                        if redirect_counter > domain_rule.min_redirect_yparam:
                            flagged_case_in_rules += 1

                    # case DomainDetectionCase.REDIRECT_RANK:
                    #   if final_url != "":
                    #       trigger_rank = domain_rule.redirect_extra_yparam["trigger_rank"]
                    #       use_local_pagerank = domain_rule.redirect_extra_yparam["use_build_in_pagerank"]
                    #       if use_local_pagerank:
                    #           r = ddf.compare_redirect_page_rank_local_dict(
                    #             web_url, final_url, trigger_rank,_PAGERANK_DB
                    #         )
                    #       else:
                    #         r = ddf.compare_redirect_page_rank(
                    #             web_url, final_url, trigger_rank
                    #         )

                    #       if r:
                    #           flagged_case_in_rules += 1

                    case DomainDetectionCase.DOMAIN_REGISTER_YEAR:
                      min_year = domain_rule.domain_registration_period_year_yparam

                      if final_url != "":
                          result = ddf.check_registration_period(final_url, min_year)
                      else:
                          result = ddf.check_registration_period(web_url, min_year)

                      if result:
                          flagged_case_in_rules += 1

                    case DomainDetectionCase.DNS_RECORD_CHECK:
                      dns_record_check_missing = domain_rule.dns_record_check_yparam[
                          "check_missing"
                      ]

                      if final_url != "":
                          result = ddf.is_missing_dns_records(
                              final_url, dns_record_check_missing
                          )
                      else:
                          result = ddf.is_missing_dns_records(
                              web_url, dns_record_check_missing
                          )

                      if result:
                          flagged_case_in_rules += 1

                if detect_case_len == flagged_case_in_rules and detect_case_len > 0:
                    flagged_rules.append(domain_rule)
                    if score_mode:
                        domain_risk_score += domain_rule.risk_score

        return DomainDetectionResult(
            web_url=web_url,
            risk_score=domain_risk_score,
            flagged_rules=flagged_rules,
            error=flagged_rules,
        )
