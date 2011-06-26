#-------------------------------------------------------------------------------
# Copyright (c) 2011, Kafti team
# 
# Released under the MIT license. See the LICENSE file for details.
#-------------------------------------------------------------------------------

"""Module with gramar rules for parsing nasl scripts"""

import ply.yacc as yacc

import naslAST
import nasllex


tokens = nasllex.tokens

_debugging_script_mode = False

precedence = (
    ('right', 'EQUALS', 'PLUS_EQ', 'MINUS_EQ', 'MULT_EQ', 'DIV_EQ',
        'MODULO_EQ', 'L_SHIFT_EQ', 'R_SHIFT_EQ', 'R_USHIFT_EQ'),
    ('left', 'OR'),
    ('left', 'AND'),
    ('nonassoc', 'LT', 'GT', 'EQ', 'NEQ', 'SUPEQ', 'INFEQ', 'MATCH',
        'NOMATCH', 'RE_MATCH', 'RE_NOMATCH'),
    ('left', 'BIT_OR'),
    ('left', 'BIT_XOR'),
    ('left', 'BIT_AND'),
    ('nonassoc', 'R_SHIFT', 'R_USHIFT', 'L_SHIFT'),
    ('left', 'PLUS', 'MINUS'),
    ('left', 'TIMES', 'DIVIDE', 'MOD'),
    ('nonassoc', 'LNOT'),
    ('nonassoc', 'UMINUS', 'BIT_NOT'),
    ('right', 'EXPO'),
    ('nonassoc', 'PLUS_PLUS', 'MINUS_MINUS'),
    ('nonassoc', 'ARROW')
)


def p_instr_decl_list_1(p):
    '''instr_decl_list : instr_decl''' 
    p[0] = naslAST.InstrList(p[1])

def p_instr_decl_list_2(p):
    '''instr_decl_list : instr_decl instr_decl_list''' 
    p[0] = p[2]
    p[0].add_instr(p[1])
        

def p_instr_decl(p):
    '''instr_decl : instr
                  | func_decl'''
    p[0] = p[1]


# Function declaration
def p_func_decl(p):
    '''func_decl : FUNCTION identifier LPAREN arg_decl RPAREN block'''
    p[0] = naslAST.FuncDecl(p[2], p[4], p[6])

def p_arg_decl(p):
    '''arg_decl : empty
                | arg_decl_real'''
    p[0] = p[1]

def p_arg_decl_real_1(p):
    '''arg_decl_real : identifier'''
    p[0] = naslAST.ArgDeclList(p[1])

def p_arg_decl_real_2(p):
    '''arg_decl_real : identifier COMMA arg_decl_real''' 
    p[0] = p[3] 
    p[0].add_arg(p[1])


# Block
def p_block_1(p):
    '''block : LBRACE instr_list RBRACE'''
    p[0] = p[2]

def p_block_2(p):
    '''block : LBRACE RBRACE'''
    p[0] = naslAST.InstrList()


def p_instr_list_1(p):
    '''instr_list : instr'''
    p[0] = naslAST.InstrList(p[1])

def p_instr_list_2(p):
    '''instr_list : instr instr_list'''
    p[0] = p[2]
    p[0].add_instr(p[1])


# Instructions
def p_instr(p):
    '''instr : simple_instr SEMI
             | block
             | if_block
             | loop'''
    p[0] = p[1]


# "simple" instruction
def p_simple_instr_1(p):
    '''simple_instr : BREAK'''
    p[0] = naslAST.BreakInstr()

def p_simple_instr_2(p):
    '''simple_instr : CONTINUE'''
    p[0] = naslAST.ContinueInstr()

def p_simple_instr_3(p):
    '''simple_instr : post_pre_incr
                    | rep
                    | func_call
                    | ret
                    | inc
                    | loc
                    | glob'''
    p[0] = p[1]

def p_simple_instr_4(p):
    '''simple_instr : aff'''
    p[0] = p[1]

def p_simple_instr_5(p):
    '''simple_instr : empty'''


# return
def p_ret_1(p):
    '''ret : RETURN expr'''
    p[0] = naslAST.ReturnInstr(p[2])

def p_ret_2(p):
    '''ret : RETURN empty'''
    p[0] = naslAST.ReturnInstr()


# If block
def p_if_block_1(p):
    '''if_block : IF LPAREN expr RPAREN instr'''
    p[0] = naslAST.IfBlock(p[3], p[5])

def p_if_block_2(p):
    '''if_block : IF LPAREN expr RPAREN instr ELSE instr'''
    p[0] = naslAST.IfBlock(p[3], p[5], p[7])


# Loops
def p_loop(p):
    '''loop : for_loop
            | while_loop
            | repeat_loop
            | foreach_loop'''
    p[0] = p[1]

def p_for_loop(p):
    '''for_loop : FOR LPAREN aff_func SEMI expr SEMI aff_func RPAREN instr''' 
    p[0] = naslAST.ForLoop(p[3], p[5], p[7], p[9])

def p_while_loop(p):
    '''while_loop : WHILE LPAREN expr RPAREN instr'''
    p[0] = naslAST.WhileLoop(p[3], p[5])

def p_repeat_loop(p):
    '''repeat_loop : REPEAT instr UNTIL expr SEMI'''
    p[0] = naslAST.RepeatLoop(p[2], p[4])

def p_foreach_loop(p):
    '''foreach_loop : FOREACH identifier LPAREN expr RPAREN  instr''' 
    p[0] = naslAST.ForeachLoop(naslAST.VarName(p[2]), p[4], p[6])


# affectation or function call
def p_aff_func(p):
    '''aff_func : aff
                | post_pre_incr
                | func_call
                | empty'''
    p[0] = p[1]


# repetition
def p_rep(p):
    '''rep : func_call REP expr'''
    p[0] = naslAST.Repetition(p[1], p[3])

#def p_(p):
#string : STRING1 { $$ = $1.val; } | STRING2 ;


# include
def p_inc(p):
    '''inc : INCLUDE LPAREN STRING RPAREN'''
    p[0] = naslAST.Include(p[3])


# Function call
def p_func_call(p):
    '''func_call : identifier LPAREN arg_list RPAREN'''
    p[0] = naslAST.FuncCall(p[1], p[3])

def p_arg_list(p):
    '''arg_list : arg_list_real
                | empty'''
    p[0] = p[1]

def p_arg_list_real_1(p):
    '''arg_list_real : arg'''
    p[0] = naslAST.ArgList(p[1])

def p_arg_list_real_2(p):
    '''arg_list_real : arg COMMA arg_list_real'''
    p[0] = p[3]
    p[0].add_arg(p[1])

def p_arg_1(p):
    '''arg : expr''' 
    p[0] = naslAST.Arg(p[1])

def p_arg_2(p):
    '''arg : identifier COLON expr''' 
    p[0] = naslAST.ArgAttribute(p[1], p[3])


# Affectation
def p_aff(p):
    '''aff : lvalue EQUALS expr
           | lvalue PLUS_EQ expr
           | lvalue MINUS_EQ expr
           | lvalue MULT_EQ expr
           | lvalue DIV_EQ expr
           | lvalue MODULO_EQ expr
           | lvalue R_SHIFT_EQ expr 
           | lvalue R_USHIFT_EQ expr 
           | lvalue L_SHIFT_EQ expr''' 
    p[0] = naslAST.Affectation(p[1], p[2], p[3])

def p_lvalue_1(p):
    '''lvalue : identifier'''
    p[0] = naslAST.VarName(p[1])

def p_lvalue_2(p):
    '''lvalue : array_elem'''
    p[0] = p[1]


def p_identifier(p):
    '''identifier : ID
                  | REP'''
    p[0] = p[1]

def p_array_elem(p):
    '''array_elem : identifier LBRACKET array_index RBRACKET'''
    p[0] = naslAST.ArrayElem(p[1], p[3])

def p_array_index(p):
    '''array_index : expr'''
    p[0]=p[1]

def p_post_pre_incr_1(p):
    '''post_pre_incr : PLUS_PLUS lvalue
                     | MINUS_MINUS lvalue'''
    p[0] = naslAST.PreIncr(p[1], p[2])

def p_post_pre_incr_2(p):
    '''post_pre_incr : lvalue PLUS_PLUS
                     | lvalue MINUS_MINUS'''
    p[0] = naslAST.PostIncr(p[1], p[2])


# expression. We accept affectations inside parenthesis
def p_expr_1(p):
    '''expr : expr AND expr 
            | expr OR expr 
            | expr PLUS expr 
            | expr MINUS expr 
            | expr TIMES expr 
            | expr EXPO expr 
            | expr DIVIDE expr 
            | expr MOD expr 
            | expr BIT_AND expr 
            | expr BIT_XOR expr 
            | expr BIT_OR expr 
            | expr R_SHIFT expr 
            | expr R_USHIFT expr 
            | expr L_SHIFT expr 
            | expr MATCH expr
            | expr NOMATCH expr
            | expr RE_MATCH STRING
            | expr RE_NOMATCH STRING
            | expr LT expr
            | expr GT expr
            | expr EQ expr
            | expr NEQ expr
            | expr SUPEQ expr
            | expr INFEQ expr'''
    p[0] = naslAST.Expression(p[1], p[2], p[3])

def p_expr_2(p):
    '''expr : MINUS expr %prec UMINUS
            | BIT_NOT expr 
            | LNOT expr'''
    p[0] = naslAST.RExpression(p[1], p[2])
        
def p_expr_3(p):
    '''expr : post_pre_incr'''
    p[0] = p[1]

def p_expr_4(p):
    '''expr : var
            | ipaddr
            | atom
            | const_array
            | aff'''
    p[0] = p[1]

def p_expr_5(p):
    '''expr : LPAREN expr RPAREN'''
    p[0] = p[2]


def p_const_array(p):
    '''const_array : LBRACKET list_array_data RBRACKET'''
    p[0] = naslAST.ConstArray(p[2])


def p_list_array_data_1(p):
    '''list_array_data : array_data'''
    p[0] = naslAST.ArrayDataList(p[1])

def p_list_array_data_2(p):
    '''list_array_data : array_data COMMA list_array_data'''
    p[0] = p[3]
    p[0].add_elem(p[1])


def p_array_data_1(p):
    '''array_data : simple_array_data'''
    p[0] = p[1]

def p_array_data_2(p):
    '''array_data : STRING ARROW simple_array_data'''
    p[0] = ('array_data', p[1], p[3])
    raise NotImplementedError


def p_atom(p):
    '''atom : INTEGER
            | STRING'''
    p[0] = naslAST.Atom(p[1])

def p_simple_array_data(p):
    '''simple_array_data : atom'''
    p[0] = p[1]

def p_var(p):
    '''var : var_name
           | array_elem
           | func_call'''
    p[0] = p[1]

def p_var_name(p):
    '''var_name : identifier'''
    p[0] = naslAST.VarName(p[1])

def p_ipaddr(p):
    '''ipaddr : INTEGER DOT INTEGER DOT INTEGER DOT INTEGER''' 
    p[0] = naslAST.IpAddr('.'.join([p[1], p[3], p[5], p[7]]))

# Local variable declaration
def p_loc(p):
    '''loc : LOCAL arg_decl'''
    p[0] = naslAST.LocalVar(p[2])

# Global variable declaration
def p_glob(p):
    '''glob : GLOBAL arg_decl''' 
    p[0] = naslAST.GlobalVar(p[2])

def p_empty(p):
    'empty :'
    p[0] = naslAST.Empty()


# Error rule for syntax errors
def p_error(p):
    if _debugging_script_mode:
        print "Syntax error at token", p.type, p.value
        yacc.errok()
    else:
        raise SyntaxError


def naslparser(file_name, debugging_script=False):
    global _debugging_script_mode
    _debugging_script_mode = debugging_script    
    parser = yacc.yacc()
    s = open(file_name).read()
    return parser.parse(s)

def _print_AST(file_name):
    result = naslparser(file_name, True)
    print(result)

def _test_parser_for_plugins(plug_dir):
    import os.path
    from pprint import pprint
    
    global _debugging_script_mode
    _debugging_script_mode = False
    parser = yacc.yacc()

    files_w_problem = []
    files_wo_problem = []    

    for file_name in os.listdir(plug_dir):
        full_path = os.path.join(plug_dir, file_name)
        if os.path.isfile(full_path) and full_path.endswith(('.inc', '.nasl')):
            s = open(full_path).read()
            try:
                parser.parse(s)
            except:
                files_w_problem.append(file_name)
            else:
                files_wo_problem.append(file_name)
    
    print "Files with problems ", len(files_w_problem)
    pprint(files_w_problem[:5])
    print "\n\nFiles withot problems ", len(files_wo_problem)
    pprint(files_wo_problem[:3])
    

if __name__ == "__main__":
    import os
    
    #_print_AST(r"c:\Program Files\Tenable\Nessus\nessus\plugins\lltd_discover.nasl")
    _print_AST(os.path.join(os.environ['KAFTI_NASLSCRIPTS_PATH'], "http_version.nasl"))
    #_test_parser_for_plugins(r"d:\projects\naslscripts.git")
    #_test_parser_for_plugins(r"c:\Program Files\Tenable\Nessus\nessus\plugins")
