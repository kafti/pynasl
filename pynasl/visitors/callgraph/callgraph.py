#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""Visitor for generate call graph of functions in nasl scripts"""

import os
import logging
from collections import defaultdict

import networkx as nx

from pynasl.naslAST import BaseNodeVisitor


logger = logging.getLogger("CallGraph")
logger.setLevel(logging.INFO)


class CallGraph(BaseNodeVisitor):
    def __init__(self):
        self.g = nx.DiGraph()
        self.caller_func = None
        self.file_name = None
    
    def visit_FuncCall(self, node):
        if node.name == "script_dependencies":
            for script_dependencies in self.visit(node.args_list): 
                self.g.add_edge(self.caller_func, script_dependencies)
            pass
        else:
            if self.caller_func is None:
                self.g.add_node(node.name)
            else:
                self.g.add_edge(self.caller_func, node.name)        
            
            self.generic_visit(node)
    
    def visit_FuncDecl(self, node):
        prev_caller_func = self.caller_func
        self.caller_func = node.name
        
        self.g.add_node(node.name)
        self.g.node[node.name]['file_name'] = self.file_name
        
        self.generic_visit(node)
        self.caller_func = prev_caller_func
        
    def visit_ArgList(self, node):
        args = [arg.value.value.replace('"', '') for arg in node.args]
        return args
    
    def set_caller_func(self, name):
        self.caller_func = name
    
    def set_file_name(self, name):
        self.file_name = name


def generate_graph(dir, script_name=None):
    
    from pynasl.naslparse import naslparser
    
    logger.info("Generating graph started")
    
    call_tree = CallGraph()
    total_files = 0
    for root,dirs,files in os.walk(dir):
        for name in files:
            if name.endswith('.inc') or (name.endswith('.nasl') and (script_name is None or script_name == name)):
                fullname = os.path.join(root, name)
                call_tree.set_caller_func(name)
                call_tree.set_file_name(name)
                
                call_tree.visit(naslparser(fullname, True))
                
                total_files += 1
                if total_files % 1000 == 0:
                    logger.info("Processed %s files" % total_files)
    
    logger.info("Generated graph with %s nodes and %s edges. Processed %s files" % 
                (call_tree.g.number_of_nodes(), call_tree.g.number_of_edges(), total_files))
    
    return call_tree.g


def _save_graph(graph, file_name='graph'):
    nx.write_gexf(graph, file_name + '.gexf')


def _open_graph(file_name):
    file_name += '.gexf'
    try:
        graph = nx.read_gexf(file_name)
        logger.info("Use saved graph in %s" % file_name)
    except IOError, why: 
        logger.error("Can't open saved graph. Error: %s" % why)
        graph = None
    
    return graph


def _print_function(tree):
    internal_function = []
    func_call = defaultdict(list)
    for node in tree.nodes_iter(data=True):
        function = node[0]
        atr = node[1]
        
        if atr:
            f_n = atr['file_name']
            func_call[f_n].append(function)
        else:
            internal_function.append(function)
    
    internal_function.remove(script_name)
    
    print "Internal function:"
    print internal_function
    print "Call function:"
    print func_call

    
def _cut_description_function(tree):
    
    description_function = ['script_add_preference',
                            'script_bugtraq_id',
                            'script_category',
                            'script_copyright',
                            'script_cve_id',
                            'script_dependencie',
                            #'script_dependencies',
                            'script_description',
                            'script_exclude_keys',
                            'script_family',
                            'script_get_preference',
                            'script_id',
                            'script_name',
                            'script_require_keys',
                            'script_require_ports',
                            'script_require_udp_ports',
                            'script_summary',
                            'script_timeout',
                            'script_tag',
                            'script_version']
    
    tree.remove_nodes_from(description_function)
    return tree


def _generate_call_graph(script_name, plugins_dir, dependencies=False):
    """Generate call graph for script and save result in 'script_name'.gexf
    
    @param script_name: string with script name for generating call graph    
    @param plugins_dir: string with path to nasl scripts
    @param dependencies: True, that means generate graph with dependencies file in 'script_dependencies', 
         save result in 'script_name_depend'.gexf, and save full call graph if it not exist.
         Default value - False, that means not generate graph with dependencies file in 'script_dependencies'
    @return generated graph
    """
    
    import networkx.algorithms.traversal.breadth_first_search as nx_breadth_first_search

    save_graph_name = script_name
    full_graph_name = 'full_call_graph'
    
    if dependencies:
        graph = _open_graph(full_graph_name)
        if graph is None:   
            graph = generate_graph(plugins_dir)
            _save_graph(graph, full_graph_name)
        save_graph_name += '_depend' 
    else:
        graph = generate_graph(plugins_dir, script_name)
    
    tree = nx_breadth_first_search.bfs_tree(graph, script_name)
    tree = graph.subgraph(tree.nodes())
    
    tree = _cut_description_function(tree)
    
    #_print_function(tree)
    #_print_tree(tree)
    
    _save_graph(tree, (save_graph_name))
    
    return tree


if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s  %(levelname)-8s %(name)-20s %(message)s',
                        datefmt='%H:%M:%S')
    
    logger.info('Processing started')
    
    #script_name = "secpod_apache_mod_proxy_ajp_info_disc_vuln.nasl"
    script_name = 'gb_7zip_detect_win.nasl'
    plugins_dir = os.environ['KAFTI_NASLSCRIPTS_PATH']
    
    graph = _generate_call_graph(script_name, plugins_dir, dependencies=True)
    
    logger.info('Processing finished')
