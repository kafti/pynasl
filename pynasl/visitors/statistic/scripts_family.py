#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""
Visitor for collecting nasl scripts family statistic.
Module can categorize nasl script into directories based on its family
"""

import os
import shutil
import logging
from collections import defaultdict

from pynasl.naslAST import BaseNodeVisitor
from pynasl.visitors.statistic.statistic import write_func_dict_to_csv


logger = logging.getLogger("scripts_family")
logger.setLevel(logging.INFO)


class FamilyGetter(BaseNodeVisitor):
    def __init__(self):
        self.variables = {}
        self.family_name = None
        
    def visit_FuncCall(self, node):
        self.generic_visit(node)
        if node.name == "script_family":
            self.family_name = node.args_list.args[0].value.value
            if self.family_name in self.variables:
                self.family_name  = self.variables[self.family_name]
            
    def visit_Affectation(self, node):
        self.generic_visit(node)
        str_lvalue = node.lvalue.value
        str_expr = node.expr.value
        if node.operation == "=":
            self.variables[str_lvalue] = str_expr


def _log_family(plugins_dir, categorize_path=None):
    """logger script_family
    
    @param plugins_dir: string with path to directory with nasl scripts.
    @param categorize_path: string with path to directory
        to which nasl scripts will be categorized.
        Default value - None, that means not categorize nasl scripts.
    """
    from pynasl.naslparse import naslparser
    
    scripts_family = defaultdict(list)
    strange_family = []
    
    if categorize_path:
        if not os.path.exists(categorize_path):
            os.makedirs(categorize_path)
        else:
            shutil.rmtree(categorize_path)
        
    logger.info('Files processing started')
    total_files = 0
    for root, dirs, files in os.walk(plugins_dir):
        for name in files:
            if not name.endswith('.nasl'):
                continue
            
            family = FamilyGetter()
            full_path = os.path.join(root, name)
            family.visit(naslparser(full_path, True))
            
            if not family.family_name:
                strange_family.append(name)
            else:
                family_name = family.family_name[1:-1].replace(':','')
                scripts_family[family_name].append(name)
                
                if categorize_path:
                    dst = os.path.join(categorize_path, family_name)
                    try:
                        if not os.path.exists(dst):
                            os.makedirs(dst)
                        shutil.copy(full_path, dst)
                    except OSError, why:
                        logger.error(str(why))

            total_files += 1
            if total_files % 1000 == 0:
                logger.info("Processed %s files" % total_files)
    logger.info('Files processing finished')
                            
    write_func_dict_to_csv(scripts_family, "scripts_family.csv")
    
    
    logger.info("*.nasl files contain %s different script_family" % len(scripts_family))
    logger.info("Detailed statistic is in scripts_family.txt")
    logger.info("%s scripts has strange family" % len(strange_family))
    logger.info('%s' % strange_family)


if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s  %(levelname)-8s %(name)-20s %(message)s',
                        datefmt='%H:%M:%S')
    _log_family(os.environ['KAFTI_NASLSCRIPTS_PATH'], r'd:\temp')
