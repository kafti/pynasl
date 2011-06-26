#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

# R0904:    Too many public methods (%s/%s) Used when class has too many public methods,
#           try to reduce this to get a more simple (and so easier to use) class.
# W0231:    __init__ method from base class %r is not called
#           Used when an ancestor class method has an __init__ method which is not called
#           by a derived class.
# pylint: disable=R0904,W0231
"""Visitor for translating scripts from nasl to python"""

import os
import re

from pynasl.naslAST import NodeVisitor, VarName, InstrList


class Translator(NodeVisitor):
    STATE_GET_METADATA = 0
    STATE_MAIN_CODE = 1
    
    def __init__(self):
        self._tab_str = ' ' * 4
        self._indent_level = -1
        self._state = None
        self._imports = []
        
    def _indent_lines(self, lines, after=None):
        if after:
            lines = lines.splitlines()
            after_index = lines.index(after)
            res = []
            for index, line in enumerate(lines):
                if index > after_index:
                    res.append(self._tab_str + line)
                else:
                    res.append(line)
            return '\n'.join(res)
        else:
            return '\n'.join([self._tab_str + line for line in lines.splitlines()])

    def visit_Atom(self, node):
        
        if node.value[0] == '"' and re.search(r'\\[^nt]', node.value):
            return "r%s" % node.value
        else:
            return "%s" % node.value

    def visit_IpAddr(self, node):
        return "IpAddress(%s)" % node.value

    def visit_VarName(self, node):
        nasl_to_py = {'NULL': 'None',
                      'TRUE': 'True'}
        
        if self._state == self.STATE_GET_METADATA and node.value.isupper():
            return "ACT_TYPES.%s" % node.value
        elif node.value in nasl_to_py:
            return nasl_to_py[node.value]
        else:
            return "%s" % node.value

    def visit_LocalVar(self, node):
        #return "LocalVar(%s)" % node.value
        return ''

    def visit_GlobalVar(self, node):
        return "GlobalVar(%s)" % node.value

    def visit_Arg(self, node):
        str_value = self.visit(node.value)
        return "%s" % str_value

    def visit_ArgAttribute(self, node):
        nasl_to_py = {'socket': 'soc'}
        node.att_name = nasl_to_py.get(node.att_name, node.att_name)
        
        str_value = self.visit(node.value)
        return (node.att_name, str_value)

    def visit_FuncCall(self, node):
        if self._state == self.STATE_GET_METADATA and node.name == 'exit':
            self._state = self.STATE_MAIN_CODE
            return "\nreturn metadata"
        elif self._state == self.STATE_MAIN_CODE and node.name == 'exit':
            return "return"
        
        str_args = self.visit(node.args_list)
        
        # all script_* functions
        if node.name.startswith('script_'):
            if node.name in ('script_require_ports', 'script_tag'):
                return 'metadata.set_' + node.name + '(' + str_args + ')'
            elif node.name == 'script_dependencie':
                return 'metadata.' + node.name + ' = [' + str_args + ']'
            else:
                return 'metadata.' + node.name + ' = ' + str_args
        
        # other functions
        
        # functions which have same names in python but different behavior  
        nasl_to_py = {'string': 'nasl_string',
                      'ord': 'nasl_ord',
                      'int': 'nasl_int'}
        node.name = nasl_to_py.get(node.name, node.name)
        
        return "%s(%s)" % (node.name, str_args)

    def visit_FuncDecl(self, node):
        str_args = self.visit(node.args)
        str_elems = self.visit(node.elems)
        return "def %s(%s):%s" % (node.name, str_args, str_elems)

    def visit_ArgList(self, node):
        args = [self.visit(arg) for arg in node.args]
        
        # one simple argument
        if len(args) == 1 and isinstance(args[0], str):
            return "%s" % args[0]
        elif all([isinstance(x, str) for x in args]):
            return ', '.join(args)
        elif all([isinstance(x, tuple) for x in args]):
            return ', '.join(['%s=%s' % (x[0], x[1]) for x in args])
        else:
            return "%s" % str(args)#', '.join([str(x) for x in args])

    def visit_ArgDeclList(self, node):
        str_args = ", ".join(node.args)
        return "ArgDeclList%s" % str_args

    def visit_InstrList(self, node):
        self._indent_level += 1

        instr = '\n'.join([self.visit(elem) for elem in node.elems])
        res = instr
        if self._indent_level > 0:
            res = self._indent_lines("%s\n\n" % instr)
        else: # top level, we need to tab code in 'def main()' and append run code
            self._indent_level += 1
            res = self._indent_lines(res, 'def main():')
            self._indent_level -= 1
            res += "\nif __name__ == '__main__':\n" + \
                    self._tab_str + 'import sys\n' + \
                    self._tab_str + 'from nasllibs.core.context import context\n\n' + \
                    self._tab_str + 'try:\n' + \
                    self._tab_str * 2 + 'import _settings\n' + \
                    self._tab_str + 'except ImportError:\n' + \
                    self._tab_str * 2 + 'pass\n\n' + \
                    self._tab_str + 'context.from_argv(sys.argv)\n' + \
                    self._tab_str + 'main()\n'

        self._indent_level -= 1
        
        if self._indent_level == -1:
            res = '\n'.join(self._imports) + '\n\n\n' + res
        
        return res

    def visit_IfBlock(self, node):
        # if(description)
        if isinstance(node.condition, VarName) and \
                node.condition.value == 'description':
            self._state = self.STATE_GET_METADATA
            str_elems = self.visit(node.elems)
            
            self._imports.append('from nasllibs.core import *')
            self._imports.append('from nasllibs.scriptmetadata import *')
            
            ret = 'def get_metadata():\n' + \
                    '%smetadata = ScriptMetadata()\n' % self._tab_str + \
                    '%s' % str_elems + \
                    '\n\ndef main():'
            return ret
        
        # others
        str_condition = self.visit(node.condition)
        str_elems = self.visit(node.elems)
        
        # InstList increase indent level
        # Single instruction don't - we must add tab manually  
        if not isinstance(node.elems, InstrList):
            str_elems = self._tab_str + str_elems 
        
        if node.else_instr:
            str_else_instr = self.visit(node.else_instr)
            # InstList increase indent level
            # Single instruction don't - we must add indent manually  
            if not isinstance(node.else_instr, InstrList):
                str_else_instr = self._tab_str + str_else_instr
            
            return "\nif %s:\n%s\nelse:\n%s" % (str_condition, str_elems, str_else_instr)
        else:
            return "\nif %s:\n%s" % (str_condition, str_elems)

    def visit_Affectation(self, node):
        str_lvalue = self.visit(node.lvalue)
        str_expr = self.visit(node.expr)
        
        # multiline string
        if str_expr[0] == '"' and '\n' in str_expr:
            return '%s %s ""%s""' % (str_lvalue, node.operation, str_expr)
        else:
            return "%s %s %s" % (str_lvalue, node.operation, str_expr)

    def visit_Repetition(self, node):
        str_func = self.visit(node.func)
        str_expr = self.visit(node.expr)
        return "Repetition(%s %s)" % (str_func, str_expr)

    def visit_Include(self, node):
        self._imports.append("from nasllibs.%s import *" % node.filename[1:-1].replace('.inc', ''))
        return ''

    def visit_Expression(self, node):
        str_lexpr = self.visit(node.lexpr)
        str_rexpr = self.visit(node.rexpr)
        
        nasl_to_py = {'||': 'or',
                     '>!<': 'not in',
                     '><': 'in'}
        
        if node.operation  == '+':
            # nasl can concatenate str and int, python can't
            # TODO: concatenate str var and int var
            # (may be through determining type of var when var is created)
            if '"' in str_lexpr and '"' not in str_rexpr:
                str_rexpr = ' + '.join(['str(%s)' % part for part in str_rexpr.split(' + ')])
            elif '"' not in str_lexpr and '"' in str_rexpr:
                str_lexpr = ' + '.join(['str(%s)' % part for part in str_lexpr.split(' + ')])

            return "%s %s %s" % (str_lexpr, node.operation, str_rexpr)
        elif node.operation in ('-', '==', '!='):
            return "%s %s %s" % (str_lexpr, node.operation, str_rexpr)
        elif node.operation in nasl_to_py:
            return "%s %s %s" % (str_lexpr, nasl_to_py[node.operation], str_rexpr)
        else:
            return "Expression(%s %s %s)" % (str_lexpr, node.operation, str_rexpr)

    def visit_RExpression(self, node):
        str_rexpr = self.visit(node.rexpr)
        if node.operation == '!':
            return 'not %s' % str_rexpr
        else:
            return "Expression(%s %s)" % (node.operation, str_rexpr)

    def visit_PostIncr(self, node):
        str_value = self.visit(node.value)
        return "%s%s" % (str_value, node.operation)        

    def visit_PreIncr(self, node):
        str_value = self.visit(node.value)
        return "%s%s" % (node.operation, str_value)        

    def visit_ArrayElem(self, node):
        str_index = self.visit(node.index)
        return "%s[%s]" % (node.name, str_index)

    def visit_ArrayDataList(self, node):
        str_elems = ', '.join([self.visit(elem) for elem in node.elems])
        return "ArrayDataList(%s)" % str_elems

    def visit_ConstArray(self, node):
        str_elems = self.visit(node.elems)
        return "ConstArray[%s]" % str_elems

    def visit_ForLoop(self, node):
        str_init = self.visit(node.init)
        str_condition = self.visit(node.condition)
        str_increment = self.visit(node.increment)
        str_elems = self.visit(node.elems)
        return "\nfor (%s; %s; %s)\n%s" % (str_init, str_condition, 
                                         str_increment, str_elems)

    def visit_ForeachLoop(self, node):
        str_element = self.visit(node.element)
        str_expr = self.visit(node.expr)
        str_elems = self.visit(node.elems)
        return "\nforeach %s in %s\n%s" % (str_element, str_expr, str_elems)

    def visit_WhileLoop(self, node):
        str_expr = self.visit(node.expr)
        str_elems = self.visit(node.elems)
        return "\nwhile %s\n%s" % (str_expr, str_elems)

    def visit_RepeatLoop(self, node):
        str_expr = self.visit(node.expr)
        str_elems = self.visit(node.elems)
        return "\nrepeat\n%s\nuntil %s" % (str_elems, str_expr)

    def visit_BreakInstr(self, node):
        return "\nbreak\n"

    def visit_ContinueInstr(self, node):
        return "\ncontinue\n"

    def visit_ReturnInstr(self, node):
        if node.expr:
            str_expr = self.visit(node.expr)
        else:
            str_expr = 'None'
        return "return %s\n" % str_expr

    def visit_Empty(self, node):
        return ''


def ast2py_str(path):
    from pynasl.naslparse import naslparser
    
    ast_string = Translator()
    return ast_string.visit(naslparser(path, True)) 
    

def _print_and_save_ast(script_name):
    module_str = ast2py_str(os.path.join(os.environ['KAFTI_NASLSCRIPTS_PATH'], script_name))
    print(module_str)
    
    new_script_name = os.path.join(os.environ['KAFTI_PYNASLSCRIPTS_PATH'],
                                   script_name[:-(len('.nasl'))] + '.py') 
    with open(new_script_name, 'w+') as f:
        f.write(module_str)
    

if __name__ == "__main__":
#    _print_and_save_ast("secpod_apache_detect.nasl")
    _print_and_save_ast("http_version.nasl")
#    _print_and_save_ast("secpod_apache_mod_proxy_ajp_info_disc_vuln.nasl")
    
