import logging
import traceback
import yaml
import os

from detectionattrenum.detect_mode import DetectMode

from .cases_style_rule import CasesStyleRule



class Yaml_Rule_Cases_Parser:
    def __init__(self, root_folder:str)-> CasesStyleRule:
        self.root_folder:str = root_folder
        
    def parses_cases_style_rule(self) -> list[CasesStyleRule] :
        
        cases_style_rules : list[CasesStyleRule] = []
        for root, _, files in os.walk(self.root_folder):
            for file in files:

                if file.endswith('.yaml'):  # Only process YAML files
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        try:
                            yaml_data = yaml.safe_load(f) or {}  # Handle empty YAML files
                            detect_mode = DetectMode.SCORE
                            try:
                                if yaml_data["mode"] == "ratio":
                                    detect_mode = DetectMode.CASE_RATIO_FLAG
                                
                                
                                if "flag_score" in yaml_data:
                                    csrule = CasesStyleRule(yaml_data['title']
                                                            , yaml_data['description']
                                                            , yaml_data['author']
                                                            , yaml_data['date']
                                                            , detect_mode
                                                            , flag_score= yaml_data["flag_score"]
                                                            )
                                
                                if "flag_ratio" in yaml_data:
                                    csrule = CasesStyleRule(yaml_data['title']
                                                            , yaml_data['description']
                                                            , yaml_data['author']
                                                            , yaml_data['date']
                                                            , detect_mode
                                                            , ration_flag = yaml_data["flag_ratio"]
                                                            )
                                
                                
                                csrule._inject_parsed_rules(cases=yaml_data['cases'])
                                cases_style_rules.append(csrule)
                            except Exception as e:
                                traceback.print_exc()
                                logging.error(f"Format Error {file_path}: {e}")
                         
                        except yaml.YAMLError as e:
                            logging.error(f"Error loading {file_path}: {e}")
                                     
        return cases_style_rules
                    
            
                              


            