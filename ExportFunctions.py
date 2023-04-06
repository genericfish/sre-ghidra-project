# Exports all functions in current program into "functions.json"

# @category: C3
# @author: Team 7.1

import os
import json
from functools import reduce
import re

# https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
from ghidra.program.flatapi import FlatProgramAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html
from ghidra.app.decompiler import *

#https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html
from ghidra.program.model.pcode import PcodeOp

prog = FlatProgramAPI(currentProgram, monitor)
decomp = FlatDecompilerAPI(prog)

currentFunction = prog.getFunctionContaining(currentAddress)

decomp.initialize()
decompIfc = decomp.getDecompiler()

cwd = os.path.dirname(os.path.realpath(__file__))

functions = {}
func = prog.getFirstFunction()

def extract_tokens(node, clang_token_types):
    # Get tokens from ClangTokenGroup AST matching types in clangTokens
    valid = reduce(lambda acc, val: acc or val, list(map(lambda token: isinstance(node, token), clang_token_types)), False)

    if not valid:
        tokens = []

        for i in range(node.numChildren()):
            child = node.Child(i)
            tokens += extract_tokens(child, clang_token_types)

        return tokens

    return [node]

def stmt_is_stl_io(node):
    # Given a ClangStatement, determine whether C++ STL IO operations i.e.:
    # insertion into std::cout or extraction from std::cin are occuring.
    nodeStr = str(node)

    if re.search("operator[<<|>>]", nodeStr) is None:
        return False

    if re.search("std::c[in|out]", nodeStr):
        return True

    for i in range(node.numChildren()):
        child = node.Child(i)

        if isinstance(child, ClangVariableToken):
            high = child.getHighVariable()

            if high is not None and re.search("basic_.stream", high.getDataType().getDisplayName()):
                    return True

    return False

def print_all_children(node, indentLevel=0):
    indent = '\t' * indentLevel
    children = node.numChildren()

    if children == 0:
        print("{}{}".format(indent, str(node)))
        return

    for i in range(node.numChildren()):
        child = node.Child(i)
        print_all_children(child, indentLevel + 1)

class Parser():
    # Simple LALR(n) parser
    def __init__(self, tokens, skipEmpty=False):
        if skipEmpty:
            self.tokens = [token for token in tokens if not is_empty(token)]
        else:
            self.tokens = tokens
        self.idx = 0

    def curr(self):
        return self.tokens[self.idx]

    def next(self, n=1):
        if self.idx + n >= len(self.tokens):
            return None

        self.idx += n
        return self.tokens[self.idx]

    def peek(self, n=1):
        if self.idx + n >= len(self.tokens):
            return None

        return self.tokens[self.idx + n]

def cleanup_stl_io_stmt(node):
    # Given a ClangStatement with C++ STL IO operations, clean up into a more human-readable form
    assignment = ""
    stream = ""
    operation = ""
    value = ""

    tokens = [node.Child(i) for i in range(node.numChildren())]

    parser = Parser(tokens, skipEmpty=True)

    foundOperator = False
    foundStream = False
    while (parser.peek() != None):
        curr = parser.curr()

        if type(curr) == ClangSyntaxToken and str(curr).strip() == "std":
            if type(parser.peek()) == ClangOpToken and str(parser.peek()).strip() == "::":
                la2 = parser.peek(2) # (l)ook(a)head 2 tokens
                if type(la2) == ClangFuncNameToken:
                    if "operator<<" in str(la2):
                        operation = "<<"
                    elif "operator>>" in str(la2):
                        operation = ">>"

                    parser.next(3)
                    foundOperator = True
                    continue
                elif type(la2) == ClangSyntaxToken and re.search("basic_.stream", str(la2)):
                    la4 = parser.peek(4) # (l)ook(a)head 4 tokens
                    if type(la4) == ClangFuncNameToken:
                        if "operator<<" in str(la4):
                            operation = "<<"
                        elif "operator>>" in str(la4):
                            operation = ">>"

                        parser.next(5)
                        foundOperator = True
                        continue

        if not foundOperator:
            assignment += str(curr)

        if foundStream and type(curr) == ClangVariableToken:
            value = str(curr)

            if re.search("PTR_endl<.*>", value):
                value = "std::endl"

            break
        elif foundOperator:
            if type(curr) == ClangSyntaxToken and str(curr).strip() == "std":
                if type(parser.peek()) == ClangOpToken and str(parser.peek()).strip() == "::":
                    la2 = parser.peek(2)
                    if type(la2) == ClangVariableToken:
                        stream = str(curr) + str(parser.peek()) + str(la2)

                        parser.next(3)
                        foundStream = True
                        continue

            if type(curr) == ClangVariableToken:
                stream = str(curr)
                foundStream = True

        parser.next()

    return assignment + stream + operation + value

def is_empty(node):
    # Check if ClangSyntaxToken is empty string or whitespace

    return isinstance(node, ClangSyntaxToken) and len(str(node).strip()) == 0

def cleanup_STL_IO(node):
    code = ""
    for i in range(node.numChildren()):
        child = node.Child(i)

        # Use type() instead of isinstance() because we want to match exactly ClangTokenGroup, not its derived types
        if type(child) == ClangTokenGroup:
            code += cleanup_STL_IO(child)
        elif stmt_is_stl_io(child):
            code += cleanup_stl_io_stmt(child)
        else:
            code += str(child)

    return code

def is_no_op_function(node):
    # Check if a given ClangTokenGroup effectively is a no-op and can be safely ignored
    # TODO: Figure out more ways a function is effectively useless from AST analysis
    stmts = extract_tokens(node, [ClangStatement])

    return len(stmts) == 1

while func is not None:
    res = decompIfc.decompileFunction(func, 30, monitor)

    if res.decompileCompleted():
        namespace = func.getParentNamespace()
        fname = func.getName()
        clangAST = res.getCCodeMarkup()
        if namespace is not None and not namespace.isGlobal():
            fname = "{}::{}".format(namespace.getName(True), fname)

        functions[fname] = {
            "simpleName": func.getName(),
            "qualifiedNamespace": namespace.getName(True),
            "entry": func.getEntryPoint().toString(),
            "decompiled": res.getDecompiledFunction().getC(),
            "cleaned": cleanup_STL_IO(clangAST),
            "nop": is_no_op_function(clangAST)
        }

        if fname == "main":
            print(cleanup_STL_IO(clangAST))

    func = prog.getFunctionAfter(func)

with open(os.path.join(cwd, "functions.json"), 'w') as funcFile:
    funcFile.write(json.dumps(functions))

decomp.dispose()