#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------
"""Simple visitor that can print AST for specified nasl script"""

import os

from pynasl.naslAST import NodeVisitor


class AST2String(NodeVisitor):

    def visit_Atom(self, node):
        return "Atom(%s)" % node.value

    def visit_IpAddr(self, node):
        return "IpAddress(%s)" % node.value

    def visit_VarName(self, node):
        return "VarName(%s)" % node.value

    def visit_LocalVar(self, node):
        return "LocalVar(%s)" % node.value

    def visit_GlobalVar(self, node):
        return "GlobalVar(%s)" % node.value

    def visit_Arg(self, node):
        str_value = self.visit(node.value)
        return "Arg(%s)" % str_value

    def visit_ArgAttribute(self, node):
        str_value = self.visit(node.value)
        return "Arg('%s':%s)" % (node.att_name, str_value)

    def visit_FuncCall(self, node):
        str_args = self.visit(node.args_list)
        return "FuncCall('%s', %s)" % (node.name, str_args)

    def visit_FuncDecl(self, node):
        str_args = self.visit(node.args)
        str_elems = self.visit(node.elems)
        return "\nFuncDecl('%s', %s)\n%s" % (node.name, str_args, str_elems)

    def visit_ArgList(self, node):
        str_args = ', '.join([self.visit(arg) for arg in node.args])
        return "ArgList[%s]" % str_args

    def visit_ArgDeclList(self, node):
        str_args = ", ".join(node.args)
        return "ArgDeclList%s" % str_args

    def visit_InstrList(self, node):
        instr = '\n'.join([self.visit(elem) for elem in node.elems])
        return "Instructions\n%s" % instr

    def visit_IfBlock(self, node):
        str_condition = self.visit(node.condition)
        str_elems = self.visit(node.elems)
        if node.else_instr:
            str_else_instr = self.visit(node.else_instr)
            return "\nIf %s\n%s\n%s\n" % (str_condition, str_elems, str_else_instr)
        else:
            return "\nIf %s\n%s\n" % (str_condition, str_elems)

    def visit_Affectation(self, node):
        str_lvalue = self.visit(node.lvalue)
        str_expr = self.visit(node.expr)
        return "Affectation(%s %s %s)" % (str_lvalue, node.operation, str_expr)

    def visit_Repetition(self, node):
        str_func = self.visit(node.func)
        str_expr = self.visit(node.expr)
        return "Repetition(%s %s)" % (str_func, str_expr)

    def visit_Include(self, node):
        return "Include(%s)" % node.filename

    def visit_Expression(self, node):
        str_lexpr = self.visit(node.lexpr)
        str_rexpr = self.visit(node.rexpr)
        return "Expression(%s %s %s)" % (str_lexpr, node.operation, str_rexpr)

    def visit_RExpression(self, node):
        str_rexpr = self.visit(node.rexpr)
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
        return "EMPTY"


def _print_AST(file_name):
    from pynasl.naslparse import naslparser
    
    ast_string = AST2String()
    print(ast_string.visit(naslparser(file_name, True)))

if __name__ == "__main__":
    _print_AST(os.path.join(os.environ['KAFTI_NASLSCRIPTS_PATH'], "http_version.nasl"))
