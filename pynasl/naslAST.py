#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""Module defines AST nodes and base visitors which can be used for walking AST"""

import abc


class Atom(object):
    __slots__ = ['value']
    
    def __init__(self, value):
        self.value = value
        
    def __repr__(self):
        return "Atom(%s)" % self.value


class IpAddr(object):
    __slots__ = ['value']

    def __init__(self, ip):
        self.value = ip
    
    def __repr__(self):
        return "IpAddress(%s)" % self.value


class VarName(object):
    __slots__ = ['value']
    
    def __init__(self, value):
        self.value = value
        
    def __repr__(self):
        return "VarName(%s)" % self.value


class LocalVar(object):
    __slots__ = ['value']
    
    def __init__(self, value):
        self.value = value
        
    def __repr__(self):
        return "LocalVar(%s)" % self.value
    

class GlobalVar(object):
    __slots__ = ['value']
    
    def __init__(self, value):
        self.value = value
        
    def __repr__(self):
        return "GlobalVar(%s)" % self.value
    

class Arg(object):
    __slots__ = ['value']
    
    def __init__(self, value):
        self.value = value
        
    def __repr__(self):
        return "Arg(%s)" % self.value


class ArgAttribute(object):
    __slots__ = ['att_name', 'value']
    
    def __init__(self, att_name, value):
        self.att_name = att_name
        self.value = value
        
    def __repr__(self):
        return "Arg('%s':%s)" % (self.att_name, self.value)


class FuncCall(object):
    __slots__ = ['name', 'args_list']
    
    def __init__(self, name, args_list):
        self.name = name
        self.args_list = args_list
        
    def __repr__(self):
        return "FuncCall('%s', %s)" % (self.name, self.args_list)


class FuncDecl(object):
    __slots__ = ['name', 'args', 'elems']
    
    def __init__(self, name, args, instr):
        self.name = name
        self.args = args
        self.elems = instr
        
    def __repr__(self):
        return "\nFuncDecl('%s', %s)\n%s" % (self.name, self.args, self.elems)


class ArgList(object):
    __slots__ = ['args']
    
    def __init__(self, arg):
        self.args = []
        self.args.append(arg)
    
    def __repr__(self):
        return "ArgList%s" % self.args
    
    def add_arg(self, arg):
        self.args.insert(0, arg)


class ArgDeclList(object):
    __slots__ = ['args']
    
    def __init__(self, arg):
        self.args = []
        self.args.append(arg)
    
    def __repr__(self):
        return "ArgDeclList%s" % self.args
    
    def add_arg(self, arg):
        self.args.insert(0, arg)


class InstrList(object):
    __slots__ = ['elems']
    
    def __init__(self, instr=None):
        self.elems = []
        if instr:
            self.elems.append(instr)
    
    def __repr__(self):
        instr = '\n'.join([str(elem) for elem in self.elems])
        return "Instructions\n%s" % instr
    
    def add_instr(self, instr):
        self.elems.insert(0, instr)


class IfBlock(object):
    __slots__ = ['condition', 'elems', 'else_instr']
    
    def __init__(self, condition, instr, else_instr=None):
        self.condition = condition
        self.elems = instr
        self.else_instr = else_instr
    
    def __repr__(self):
        if self.else_instr:
            return "\nIf %s\n%s\nElse\n%s\n" % (self.condition, self.elems, self.else_instr)
        else:
            return "\nIf %s\n%s\n" % (self.condition, self.elems)


class Affectation(object):
    __slots__ = ['lvalue', 'operation', 'expr']
    
    def __init__(self, lvalue, operation, expr):
        self.lvalue = lvalue
        self.operation = operation
        self.expr = expr
        
    def __repr__(self):
        return "Affectation(%s %s %s)" % (self.lvalue, self.operation, self.expr)


class Repetition(object):
    __slots__ = ['func', 'expr']
    
    def __init__(self, func, expr):
        self.func = func
        self.expr = expr
    
    def __repr__(self):
        return "Repetition(%s %s)" % (self.func, self.expr)
    
        
class Include(object):
    __slots__ = ['filename']
    
    def __init__(self, filename):
        self.filename = filename
        
    def __repr__(self):
        return "Include(%s)" % self.filename


class Expression(object):
    __slots__ = ['lexpr', 'operation', 'rexpr']
    
    def __init__(self, lexpr, operation, rexpr):
        self.lexpr = lexpr
        self.operation = operation        
        self.rexpr = rexpr
    
    def __repr__(self):
        return "Expression(%s %s %s)" % (self.lexpr, self.operation, self.rexpr)


class RExpression(object):
    __slots__ = ['operation', 'rexpr']
    
    def __init__(self, operation, rexpr):
        self.operation = operation        
        self.rexpr = rexpr
    
    def __repr__(self):
        return "Expression(%s %s)" % (self.operation, self.rexpr)


class PostIncr(object):
    __slots__ = ['operation', 'value']
    
    def __init__(self, value, operation):
        self.value = value
        self.operation = operation
    
    def __repr__(self):
        return "%s%s" % (self.value, self.operation)        


class PreIncr(object):
    __slots__ = ['operation', 'value']
    
    def __init__(self, operation, value):
        self.value = value
        self.operation = operation
    
    def __repr__(self):
        return "%s%s" % (self.operation, self.value)        


class ArrayElem(object):
    __slots__ = ['name', 'index']
    
    def __init__(self, name, index):
        self.name = name
        self.index = index
        
    def __repr__(self):
        return "%s[%s]" % (self.name, self.index)


class ArrayDataList(object):
    __slots__ = ['elems']
    
    def __init__(self, elem=None):
        self.elems = []
        if elem:
            self.elems.append(elem)
    
    def __repr__(self):
        elems = ', '.join([str(elem) for elem in self.elems])
        return "ArrayDataList(%s)" % elems
    
    def add_elem(self, elem):
        self.elems.insert(0, elem)


class ConstArray(object):
    __slots__ = ['elems']
    
    def __init__(self, elems):
        self.elems = elems
    
    def __repr__(self):
        return "ConstArray[%s]" % self.elems


class ForLoop(object):
    __slots__ = ['init', 'condition', 'increment', 'elems']
    
    def __init__(self, init, condition, increment, instr):
        self.init = init
        self.condition = condition
        self.increment = increment
        self.elems = instr
    
    def __repr__(self):
        return "\nfor (%s; %s; %s)\n%s" % (self.init, self.condition, 
                                         self.increment, self.elems)
        

class ForeachLoop(object):
    __slots__ = ['element', 'expr', 'elems']
    
    def __init__(self, element, expr, instr):
        self.element = element
        self.expr = expr
        self.elems = instr
    
    def __repr__(self):
        return "\nforeach %s in %s\n%s" % (self.element, self.expr, self.elems)


class WhileLoop(object):
    __slots__ = ['expr', 'elems']
    
    def __init__(self, expr, instr):
        self.expr = expr
        self.elems = instr
    
    def __repr__(self):
        return "\nwhile %s\n%s" % (self.expr, self.elems)

        
class RepeatLoop(object):
    __slots__ = ['expr', 'elems']
    
    def __init__(self, instr, expr):
        self.expr = expr
        self.elems = instr
    
    def __repr__(self):
        return "\nrepeat\n%s\nuntil %s" % (self.elems, self.expr)


class BreakInstr(object):
    def __repr__(self):
        return "\nbreak\n"


class ContinueInstr(object):
    def __repr__(self):
        return "\ncontinue\n"


class ReturnInstr(object):
    __slots__ = ['expr']
    
    def __init__(self, expr=None):
        self.expr = expr
    
    def __repr__(self):
        return "return %s\n" % self.expr

        
class Empty(object):
    __slots__ = []
    
    def __repr__(self):
        return "EMPTY"


class BaseNodeVisitor(object):
    """
    A node visitor base class that walks the abstract syntax tree and calls a
    visitor function for every node found.  This function may return a value
    which is forwarded by the `visit` method.

    This class is meant to be subclassed, with the subclass adding visitor
    methods.

    Per default the visitor functions for the nodes are ``'visit_'`` +
    class name of the node.  So a `TryFinally` node visit function would
    be `visit_TryFinally`.  This behavior can be changed by overriding
    the `visit` method.  If no visitor function exists for a node
    (return value `None`) the `generic_visit` visitor is used instead.
    """
    
    def visit(self, node):
        """Visit a node."""
        method = 'visit_' + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        return visitor(node)
    
    def generic_visit(self, node):
        """Called if no explicit visitor function exists for a node."""
        for elem_name in node.__slots__:
            elem = getattr(node, elem_name)
            if isinstance(elem, list):
                for list_elem in elem:
                    try:
                        self.visit(list_elem)
                    except AttributeError:
                        pass
            else:
                try:
                    self.visit(elem)
                except AttributeError:
                    pass


class NodeVisitor(BaseNodeVisitor):
    """
    A node visitor abstract base class that is a template for developing
    visitors with visit_* methods for all AST nodes.
    """
    
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def visit_Atom(self, node):
        """"""

    @abc.abstractmethod
    def visit_IpAddr(self, node):
        """"""

    @abc.abstractmethod
    def visit_VarName(self, node):
        """"""

    @abc.abstractmethod
    def visit_LocalVar(self, node):
        """"""

    @abc.abstractmethod
    def visit_GlobalVar(self, node):
        """"""

    @abc.abstractmethod
    def visit_Arg(self, node):
        """"""

    @abc.abstractmethod
    def visit_ArgAttribute(self, node):
        """"""

    @abc.abstractmethod
    def visit_FuncCall(self, node):
        """"""

    @abc.abstractmethod
    def visit_FuncDecl(self, node):
        """"""

    @abc.abstractmethod
    def visit_ArgList(self, node):
        """"""

    @abc.abstractmethod
    def visit_ArgDeclList(self, node):
        """"""

    @abc.abstractmethod
    def visit_InstrList(self, node):
        """"""

    @abc.abstractmethod
    def visit_IfBlock(self, node):
        """"""

    @abc.abstractmethod
    def visit_Affectation(self, node):
        """"""

    @abc.abstractmethod
    def visit_Repetition(self, node):
        """"""

    @abc.abstractmethod
    def visit_Include(self, node):
        """"""

    @abc.abstractmethod
    def visit_Expression(self, node):
        """"""

    @abc.abstractmethod
    def visit_RExpression(self, node):
        """"""

    @abc.abstractmethod
    def visit_PostIncr(self, node):
        """"""

    @abc.abstractmethod
    def visit_PreIncr(self, node):
        """"""

    @abc.abstractmethod
    def visit_ArrayElem(self, node):
        """"""

    @abc.abstractmethod
    def visit_ArrayDataList(self, node):
        """"""

    @abc.abstractmethod
    def visit_ConstArray(self, node):
        """"""

    @abc.abstractmethod
    def visit_ForLoop(self, node):
        """"""

    @abc.abstractmethod
    def visit_ForeachLoop(self, node):
        """"""

    @abc.abstractmethod
    def visit_WhileLoop(self, node):
        """"""

    @abc.abstractmethod
    def visit_RepeatLoop(self, node):
        """"""

    @abc.abstractmethod
    def visit_BreakInstr(self, node):
        """"""

    @abc.abstractmethod
    def visit_ContinueInstr(self, node):
        """"""

    @abc.abstractmethod
    def visit_ReturnInstr(self, node):
        """"""

    @abc.abstractmethod
    def visit_Empty(self, node):
        """"""
