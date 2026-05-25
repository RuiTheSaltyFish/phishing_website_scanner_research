

class BaseRuleTemplate:
    def __init__(self,
                 title:str,
                 description:str,
                 date:str,
                 dtype:str,
                 detection:dict,
                 risk_score:int = 0,
                 ):
        self.title = title
        self.description = description
        self.date = date
        self.dtype = dtype
        self.detection = detection
        self.risk_score = risk_score

    def __repr__(self):
        return (f"DetectionRule("
                f"title='{self.title}', "
                f"description='{self.description}', "
                f"date='{self.date}', "
                f"dtype='{self.dtype}', "
                f"detection={self.detection}, "
                f"risk='{self.risk_score}')")

