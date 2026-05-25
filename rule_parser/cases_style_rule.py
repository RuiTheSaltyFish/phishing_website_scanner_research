


from .dom_rule import DomRule
from .domain_rule import DomainRule
from .url_rule import UrlRule
from detectionattrenum import DetectMode

class CasesStyleRule:
    def __init__(self,
                 title:str,
                 description:str,
                 author:str,
                 date:str,
                 mode:DetectMode,
                 ration_flag = None,
                 flag_score = 0
                 ):
        self.title:str = title
        self.description:str = description
        self.author:str = author
        self.date:str = date
        self.mode:DetectMode = mode
        self.ratio_flag:float = ration_flag 
        self.flag_score = flag_score
        self.parsed_url_rules : list[UrlRule] = []
        self.parsed_dom_rules : list[DomRule] = []
        self.parsed_domain_rules: list[DomainRule] = []


    def __repr__(self):
        return (f"CasesDetectionRule("
                f"title='{self.title}', "
                f"description='{self.description}', "
                f"author='{self.author}', "
                f"date='{self.date}', "
                f"mode='{self.mode}', "
                f"ration='{self.ratio_flag}', "
                )
                
    def _inject_parsed_rules(self,cases:list):
        for case in cases:
            match case["type"]:
                case 'url':
                    r = UrlRule(
                        title=case["case_title"],
                        description=case["case_description"],
                        author=self.author,
                        dtype=case["type"],
                        date=self.date,
                        detection=case["detection"],
                        risk_score=case["risk_score"]
                    )
                    self.parsed_url_rules.append(r)
                case 'domain':
                    r = DomainRule(
                        title=case["case_title"],
                        description=case["case_description"],
                        author=self.author,
                        dtype=case["type"],
                        date=self.date,
                        detection=case["detection"],
                        risk_score=case["risk_score"]
                    )
                    self.parsed_domain_rules.append(r)
                case 'dom':
                    r = DomRule(
                        title=case["case_title"],
                        description=case["case_description"],
                        author=self.author,
                        dtype=case["type"],
                        date=self.date,
                        detection=case["detection"],
                        risk_score=case["risk_score"]
                    )
                    self.parsed_dom_rules.append(r)
    
    
    def get_total_rules_count(self):
        return len(self.parsed_dom_rules) + len(self.parsed_url_rules) + len(self.parsed_domain_rules)