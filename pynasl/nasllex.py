#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""Module with lexical rules for parsing nasl scripts"""

import ply.lex as lex

from pynasl.exceptions import LexicalError


reserved = ('AND', 'OR', 'REPEAT', 'UNTIL', 'FOREACH', 'WHILE', 
    'BREAK', 'CONTINUE', 'FUNCTION', 'RETURN','INCLUDE', 'IF', 'ELSE', 'FOR'
)


tokens = reserved + (
    'REP', # 'x' - special case - can be both variable and token REP
    'EQ', 'NEQ', 'SUPEQ', 'INFEQ', 'BIT_AND', 'BIT_OR', 'BIT_XOR',
    'MATCH', 'NOMATCH',
    'PLUS_PLUS','MINUS_MINUS', 'L_SHIFT','R_SHIFT','R_USHIFT',
    'EXPO','PLUS_EQ','MINUS_EQ', 'MULT_EQ','DIV_EQ','MODULO_EQ',
    'L_SHIFT_EQ','R_SHIFT_EQ','R_USHIFT_EQ', 'RE_MATCH','RE_NOMATCH',
    #
    'ARROW', 'STRING', 'INTEGER', 'LPAREN',
    'PLUS', 'TIMES', 'COMMA', 'RPAREN',
    'SEMI', 'MINUS', 'LT', 'EQUALS', 'DIVIDE', 'GT',
    'LBRACE', 'RBRACE', 'COLON', 'LNOT', 'LBRACKET', 'RBRACKET',
    'BIT_NOT', 'MOD', 'DOT', 'LOCAL', 'GLOBAL',
    #
    'ID'
)


t_EQUALS    = r'='
t_PLUS      = r'\+'
t_MINUS     = r'-'
t_TIMES     = r'\*'
t_EXPO      = r'\*\*'
t_DIVIDE    = r'/'
t_MOD       = r'%'
t_BIT_AND   = r'&'
t_BIT_XOR   = r'\^'
t_BIT_OR    = r'\|'
t_LPAREN    = r'\('
t_RPAREN    = r'\)'
t_LBRACE    = r'\{'
t_RBRACE    = r'\}'
t_LBRACKET  = r'\['
t_RBRACKET  = r'\]'
t_LT        = r'<'
t_GT        = r'>'
t_LNOT      = r'!'
t_BIT_NOT   = r'~'
t_COMMA     = r'\,'
t_COLON     = r':'
t_SEMI      = r';'
t_DOT       = r'\.'
t_ARROW     = r'=>'
t_MINUS_MINUS = r'--'
t_PLUS_PLUS = r'\+\+'
t_L_SHIFT   = r'<<'
t_R_USHIFT  = r'>>>'
t_R_SHIFT   = r'>>'
t_NEQ       = r'!='
t_SUPEQ     = r'>='
t_INFEQ     = r'<='
t_MATCH     = r'><'
t_NOMATCH   = r'>!<'
t_RE_MATCH  = r'=~'
t_RE_NOMATCH= r'!~'
t_AND       = r'&&'
t_OR        = r'\|\|'
t_EQ        = r'=='
t_PLUS_EQ   = r'\+='
t_MINUS_EQ  = r'-='
t_MULT_EQ   = r'\*='
t_DIV_EQ    = r'/='
t_MODULO_EQ = r'%='
t_L_SHIFT_EQ= r'<<='
t_R_SHIFT_EQ= r'>>='
t_R_USHIFT_EQ = r'>>>='
t_INTEGER   = r'0[xX][A-Fa-f0-9]+|\d+'    
t_STRING    = r'".*?"|"(\\.|[^"])*?"|\'(\\.|[^\'])*?\''

t_ignore = ' \t'
t_ignore_COMMENT = r'\#.*'

reserved_map = dict((r.lower(), r) for r in reserved)


def t_ID(t):
    r'[A-Za-z_][A-Za-z_0-9]*'
    if t.value == 'x':
        t.type = 'REP'
    elif t.value == 'local_var':
        t.type = 'LOCAL'                
    elif t.value == 'global_var':
        t.type = 'GLOBAL'                
    else:
        t.type = reserved_map.get(t.value,"ID")
    return t


def t_NEWLINE(t):
    r'[\n\r]'
    t.lexer.lineno += 1
    #return t


def t_error(t):
    raise LexicalError(t)
    t.lexer.skip(1)


def _print_tokens(file_path):
    lexer = lex.lex()
    data = open(file_path).read()
    lexer.input(data)
    while True:
        tok = lexer.token()
        if not tok: break
        print tok

    
def _test_lexer_for_plugins(plug_dir):
    """Create Badfile contain scripts with error and
    Goodfile contain scripts without error"""
    
    import os
    from pprint import pprint
    
    lexer = lex.lex()

    files_w_problem = []
    files_wo_problem = []    

    for file in os.listdir(plug_dir):
        fullname = os.path.join(plug_dir, file)
        if os.path.isfile(fullname) and fullname.endswith('.nasl'):
            data = open(fullname).read()
            try:
                lexer.input(data)
                while lexer.token():
                    pass 
            except LexicalError:
                files_w_problem.append(file)
            else:
                files_wo_problem.append(file)
        
    print "Files with problems ", len(files_w_problem)
    pprint(files_w_problem[:5])
    print "\n\nFiles without problems ", len(files_wo_problem)
    pprint(files_wo_problem[:3])


lex.lex(debug=0)


if __name__ == "__main__":
    #_print_tokens(r"d:\projects\naslscripts.git\gb_7zip_detect_win.nasl")
    _test_lexer_for_plugins(r'd:\projects\naslscripts.git')
