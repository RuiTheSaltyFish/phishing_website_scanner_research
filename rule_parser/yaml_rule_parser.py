import os
import yaml


from .base_rule_template import BaseRuleTemplate
from .dom_rule import DomRule
from .domain_rule import DomainRule
from .url_rule import UrlRule

class YamlToRuleParser:
    def __init__(self, root_folder:str):
        self.root_folder:str = root_folder

    def yaml_to_rule(self) -> tuple[list[UrlRule], list[DomRule], list[DomainRule]]:
        url_rules : list[UrlRule] = []
        dom_rules : list[DomRule] = []
        domain_rules: list[DomainRule] = []

        # Walk through the directory and subdirectories
        for root, _, files in os.walk(self.root_folder):
            for file in files:
                if file.endswith('.yaml'):  # Only process YAML files
                    file_path = os.path.join(root, file)

                    # Extract the relative path for organized key structure
                    # relative_path = os.path.relpath(file_path, self.root_folder)

                    # Load and store YAML content
                    with open(file_path, 'r',encoding="utf-8") as f:
                        try:
                            yaml_data = yaml.safe_load(f) or {}  # Handle empty YAML files
                            # rule = BaseRuleTemplate(yaml_data['title']
                            #                         , yaml_data['description']
                            #                         , yaml_data['date']
                            #                         , yaml_data['type']
                            #                         , yaml_data['detection']
                            #                         , yaml_data['risk_score']
                            #                         )
                            match yaml_data['type']:
                                case 'url':
                                   url_rule = UrlRule(yaml_data['title']
                                                    , yaml_data['description']
                                                    , yaml_data['date']
                                                    , yaml_data['type']
                                                    , yaml_data['detection']
                                                    , yaml_data['risk_score']
                                                    )
                                   url_rules.append(url_rule)

                                case 'dom':
                                    dom_rule = DomRule(yaml_data['title']
                                                    , yaml_data['description']
                                                    , yaml_data['date']
                                                    , yaml_data['type']
                                                    , yaml_data['detection']
                                                    , yaml_data['risk_score']
                                                    )
                                    dom_rules.append(dom_rule)

                                case 'domain':
                                   domain_rule = DomainRule(yaml_data['title']
                                                    , yaml_data['description']
                                                    , yaml_data['date']
                                                    , yaml_data['type']
                                                    , yaml_data['detection']
                                                    , yaml_data['risk_score']
                                                    )
                                   domain_rules.append(domain_rule)

                        except yaml.YAMLError as e:
                            print(f"Error loading {file_path}: {e}")

        return url_rules,dom_rules,domain_rules
