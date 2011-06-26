#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""Simple visitor which can be used for counting nasl scripts with specified CVE-id"""

import os
import logging

from pynasl.naslAST import BaseNodeVisitor


logger = logging.getLogger("CountCVERefs")
logger.setLevel(logging.INFO)


class GetCVERef(BaseNodeVisitor):
    def __init__(self):
        self.found = False
        self.cve_id = None
        
    def visit_FuncCall(self, node):
        self.generic_visit(node)
        if node.name == "script_cve_id":
            if self.found:
                logger.error("Duplicate script_cve_id")
            else:
                self.cve_id = node.args_list.args[0].value.value


def _print_counts(dir):
    from pynasl.naslparse import naslparser
    
    logger.info("Counting started")
    
    files_with_cve = 0
    files_total = 0
    files_with_wrong_cve = 0
    for root,dirs,files in os.walk(dir):
        files_total += len(files)
        for name in files:
            if name.endswith('.nasl'):
                get_ref = GetCVERef()
                fullname = os.path.join(root, name)
                get_ref.visit(naslparser(fullname, True))
                # CAN - candidate
                if get_ref.cve_id and get_ref.cve_id.startswith(('"CVE', '"CAN')):
                    files_with_cve += 1
                elif get_ref.cve_id is not None:
                    logger.error("Strange CVE '%s' in file %s" % (get_ref.cve_id, name))
                    files_with_wrong_cve += 1
    
    logger.info("Counting ended")
    logger.info("Files with wrong CVE:%s" % files_with_wrong_cve)
    logger.info("Files with CVE:%s" % files_with_cve)
    logger.info("Total files:%s" % files_total)


if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s  %(levelname)-8s %(name)-20s %(message)s',
                        datefmt='%H:%M:%S')
    
    _print_counts(os.environ['KAFTI_NASLSCRIPTS_PATH'])
