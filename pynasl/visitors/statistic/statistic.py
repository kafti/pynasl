#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""Visitor for collecting nasl functions statistics"""

import os
import logging
import csv
from collections import defaultdict

from pynasl.naslAST import BaseNodeVisitor


logger = logging.getLogger("statistic")
logger.setLevel(logging.INFO)


output_dir = 'results'

# map id(stat_var_name) => path_string
# filled by write_func_dict_to_csv
_detailed_stat_file = {}


class NaslStatistic(BaseNodeVisitor):
    """Visitor for collecting nasl functions statistics
    
    @ivar FuncCall_nasl_dict: function's calls in *.nasl files
    @ivar FuncCall_inc_dict: function's calls in *.inc files
    @ivar FuncDecl_nasl_dict: function's declarations in *.nasl files
    @ivar FuncDecl_inc_dict: function's declarations in *.inc files
    @ivar Include_nasl_dict: include functions in *.nasl files
    @ivar Include_inc_dict: include functions in *.inc files
    @ivar FuncCall_dict: function's calls in all files
    @ivar FuncDecl_dict: function's declarations in all files
    @ivar internal_nasl_func_calls: internal nasl language function's calls in *.nasl files
    @ivar unused_decl_nasl: unused function's declarations in *.nasl files
    @ivar internal_func_calls: total internal nasl language function's calls
    @ivar unused_decl_inc: unused function's declarations in *.inc files
    @ivar unused_inc: unused *.inc files
    """
    
    def __init__(self):
        self.FuncCall_nasl_dict = defaultdict(list)
        self.FuncCall_inc_dict = defaultdict(list)
        
        self.FuncDecl_nasl_dict = defaultdict(list)
        self.FuncDecl_inc_dict = defaultdict(list)

        self.Include_nasl_dict = defaultdict(list)
        self.Include_inc_dict = defaultdict(list)

        self.FuncCall_dict = defaultdict(list)
        self.FuncDecl_dict = defaultdict(list)
        
        self.file_name = None
        self.inc_list = []
        
        self.internal_nasl_func_calls = {}
        self.unused_decl_nasl = {}
        self.internal_func_calls = {}
        self.unused_decl_inc = []
        self.unused_inc = []
    
    def preprocess_file(self, file_name):
        self.file_name = file_name

        if file_name.endswith('.inc'):
            self.inc_list.append(file_name)
        
    def visit_FuncCall(self, node):
        self._add_to_nasl_or_inc_dict(node.name, self.FuncCall_nasl_dict, self.FuncCall_inc_dict)
        self.FuncCall_dict[node.name].append(self.file_name)
        self.generic_visit(node)
        
    def visit_FuncDecl(self, node):
        self._add_to_nasl_or_inc_dict(node.name, self.FuncDecl_nasl_dict, self.FuncDecl_inc_dict)
        self.FuncDecl_dict[node.name].append(self.file_name)
        self.generic_visit(node)

    def visit_Include(self, node):
        self._add_to_nasl_or_inc_dict(node.filename[1:-1], self.Include_nasl_dict, self.Include_inc_dict)
        self.generic_visit(node)
    
    def _add_to_nasl_or_inc_dict(self, node_name, nasl_dict, inc_dict):
        if self.file_name.endswith('.nasl'):
            nasl_dict[node_name].append(self.file_name)
        else:
            inc_dict[node_name].append(self.file_name)
    
    def _cut_decl_function(self, funcDecl_dict, funcCall_dict):
        unused_func = []
        
        for func_name_Decl in funcDecl_dict.keys():
            if func_name_Decl in funcCall_dict.keys():
                del funcCall_dict[func_name_Decl]
            else:
                unused_func.append(func_name_Decl)
                
        return unused_func

    def finalize_calculations(self):
        self.internal_nasl_func_calls = self.FuncCall_nasl_dict.copy()
        self.unused_decl_nasl = self._cut_decl_function(self.FuncDecl_nasl_dict, self.internal_nasl_func_calls)
        self._cut_decl_function(self.FuncDecl_inc_dict, self.internal_nasl_func_calls)
        
        self.internal_func_calls = self.FuncCall_dict.copy()
        self._cut_decl_function(self.FuncDecl_dict, self.internal_func_calls)
        
        self.unused_decl_inc = [func for func in self.FuncDecl_inc_dict
                                if func not in self.FuncCall_nasl_dict and func not in self.FuncCall_inc_dict]
    
        self.unused_inc = [inc for inc in self.inc_list
                           if inc not in self.Include_nasl_dict and inc not in self.Include_inc_dict]


def create_statistic(plugins_dir):
    from pynasl.naslparse import naslparser
    
    stat = NaslStatistic()
    
    logger.info('Files processing started')
    total_files = 0
    for root,dirs,files in os.walk(plugins_dir):
        for name in files:
            if name.endswith(('.nasl', '.inc')):
                stat.preprocess_file(name)
                fullname = os.path.join(root, name)
                stat.visit(naslparser(fullname, True))

            total_files += 1
            if total_files % 1000 == 0:
                logger.info("Processed %s files" % total_files)
    logger.info('Files processing finished')
    
    stat.finalize_calculations()

    _write_detailed_statistic(stat)
    
    _write_main_statistic(stat, 'statistic.txt')


def write_func_dict_to_csv(func_dict, stat_file_name):
    with open(os.path.join(output_dir, stat_file_name), "w") as stat_file:
        writer = csv.writer(stat_file, delimiter=';', quoting=csv.QUOTE_NONE, lineterminator='\n')
        writer.writerow( ('Function name', 'Count', 'Files name') )
        for func_name in func_dict.keys():
            writer.writerow( (func_name, len(func_dict[func_name]), func_dict[func_name]) )

    _detailed_stat_file[id(func_dict)] = stat_file_name
            

def _write_detailed_statistic(stat):
    write_func_dict_to_csv(stat.FuncDecl_nasl_dict, "stat_decl_function_nasl.csv")
    write_func_dict_to_csv(stat.FuncDecl_inc_dict, "stat_decl_function_inc.csv")
    write_func_dict_to_csv(stat.FuncDecl_dict, "stat_all_decl.csv")
    write_func_dict_to_csv(stat.FuncCall_nasl_dict, "stat_call_function_nasl.csv")
    write_func_dict_to_csv(stat.FuncCall_inc_dict, "stat_call_function_inc.csv")
    write_func_dict_to_csv(stat.FuncCall_dict, "stat_all_call.csv")
    write_func_dict_to_csv(stat.Include_nasl_dict, "stat_include_nasl.csv")
    write_func_dict_to_csv(stat.Include_inc_dict, "stat_include_inc.csv")
    write_func_dict_to_csv(stat.internal_nasl_func_calls, "stat_call_function_nasl_internal.csv")   
    write_func_dict_to_csv(stat.internal_func_calls, "stat_internal.csv")
    

def _write_main_statistic(stat, file_name):
    with open(os.path.join(output_dir, file_name), 'wb') as main_stat:
        main_stat.write("DECLARATION Function\n")
        main_stat.write("-" * 100 + '\n')
        main_stat.write("*.nasl files contain %s function's declarations\n" % len(stat.FuncDecl_nasl_dict))
        main_stat.write("Detailed statistic is in %s\n\n" % _detailed_stat_file[id(stat.FuncDecl_nasl_dict)])
        
        main_stat.write("*.inc files contain %s function's declarations\n" % len(stat.FuncDecl_inc_dict))
        main_stat.write("Detailed statistic is in %s\n\n" % _detailed_stat_file[id(stat.FuncDecl_inc_dict)])
        
        main_stat.write("All files contain %s function's declarations\n" % len(stat.FuncDecl_dict))
        main_stat.write("Detailed statistic is in %s\n" % _detailed_stat_file[id(stat.FuncDecl_dict)])
        main_stat.write("-" * 100 + '\n')
        
        
        main_stat.write("CALL Function\n")
        main_stat.write("-" * 100 + '\n')
        main_stat.write("*.nasl files contain %s different function's calls\n" % len(stat.FuncCall_nasl_dict))
        main_stat.write("Detailed statistic is in %s\n\n" % _detailed_stat_file[id(stat.FuncCall_nasl_dict)])
        
        main_stat.write("*.nasl files contain %s internal function's calls\n" % len(stat.internal_nasl_func_calls))
        main_stat.write("Detailed statistic in %s\n\n" % _detailed_stat_file[id(stat.internal_nasl_func_calls)])
            
        main_stat.write("*.inc files contain %s different function's calls\n" % len(stat.FuncCall_inc_dict))
        main_stat.write("Detailed statistic is in %s\n\n" % _detailed_stat_file[id(stat.FuncCall_inc_dict)])

        main_stat.write("All files contain %s different function's calls\n" % len(stat.FuncCall_dict))
        main_stat.write("Detailed statistic is in %s\n\n" % _detailed_stat_file[id(stat.FuncCall_dict)])
        
        main_stat.write("All files contain %s internal function's calls\n" % len(stat.internal_func_calls))
        main_stat.write("Detailed statistic is in %s\n" % _detailed_stat_file[id(stat.internal_func_calls)])
        main_stat.write("-" * 100 + '\n')
        
        
        main_stat.write("USING FUNCTIONS\n")
        main_stat.write("-" * 100 + '\n')
        
        if stat.unused_decl_nasl:
            main_stat.write("Unused function's declarations in nasl scripts:\n")
            main_stat.write('%s\n\n' % stat.unused_decl_nasl)
                
        if stat.unused_decl_inc:
            main_stat.write("%s unused function's declarations in inc files:\n" % len(stat.unused_decl_inc))
            main_stat.write('%s\n\n' % stat.unused_decl_inc)
            
        main_stat.write("-" * 100 + '\n')
    
    
        main_stat.write("INCLUDE FILES\n")
        main_stat.write("-" * 100 + '\n')
        
        main_stat.write("*.nasl files contain %s different include()\n" % len(stat.Include_nasl_dict))
        main_stat.write("Detailed statistic is in %s\n\n" % _detailed_stat_file[id(stat.Include_nasl_dict)])
        
        main_stat.write("*.inc files contain %s different include()\n" % len(stat.Include_inc_dict))
        main_stat.write("Detailed statistic in %s\n\n" % _detailed_stat_file[id(stat.Include_inc_dict)])
        
        main_stat.write("%s *.inc files are unused\n" % len(stat.unused_inc))
        main_stat.write('%s\n' % stat.unused_inc)
        main_stat.write("-" * 100 + '\n')


if __name__ == "__main__":    
    logging.basicConfig(format='%(asctime)s  %(levelname)-8s %(name)-20s %(message)s',
                        datefmt='%H:%M:%S')
    create_statistic(os.environ['KAFTI_NASLSCRIPTS_PATH'])
