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


def is_empty(node):
    # Check if ClangSyntaxToken is empty string or whitespace

    return isinstance(node, ClangSyntaxToken) and len(str(node).strip()) == 0


def is_no_op_function(node):
    # Check if a given ClangTokenGroup effectively is a no-op and can be safely ignored
    # TODO: Figure out more ways a function is effectively useless from AST analysis
    stmts = extract_tokens(node, [ClangStatement])

    return len(stmts) == 1


class Parser():
    # Simple LALR(n) parser
    def __init__(self, root, skipEmpty=False):
        self.root = root
        self.skipEmpty = skipEmpty

        tokens = [root.Child(i) for i in range(root.numChildren())]

        if skipEmpty:
            self.tokens = [token for token in tokens if not is_empty(token)]
        else:
            self.tokens = tokens

        self.cursor = 0

    def curr(self):
        # Returns token at cursor
        return self.tokens[self.cursor]

    def next(self, n=1):
        # Advances cursor by n and returns token at new cursor position
        if self.cursor + n >= len(self.tokens):
            return None

        self.cursor += n
        return self.tokens[self.cursor]

    def peek(self, n=1):
        # Returns token at position cursor + n
        if self.cursor + n >= len(self.tokens):
            return None

        return self.tokens[self.cursor + n]

    def seek(self, idx):
        # Sets cursor position
        self.cursor = min(max(idx, 0), len(self.tokens) - 1)


class IOParser(Parser):
    clean = None

    def __clean_cxx_stl_io_stmt_at_cursor(self):
        # Given a ClangStatement with C++ STL IO operations, clean up into a more human-readable form
        assignment = ""
        stream = ""
        operation = ""
        value = ""

        parser = Parser(self.curr(), skipEmpty=True)

        foundOperator = False
        foundStream = False
        while parser.peek():
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
                    elif type(la2) == ClangSyntaxToken and re.search("basic_.*stream", str(la2)):
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

    def __is_cxx_stl_io_stmt(self):
        # Given a ClangStatement, determine whether C++ STL IO operations i.e.:
        # insertion into ostream or extraction from istream
        node = self.curr()
        text = str(node)

        if re.search("operator\s*[<<|>>]", text) is None:
            return False

        if re.search("std::c[in|out]", text):
            return True

        if re.search("std::basic_.*stream<.*>", text):
            return True

        for i in range(node.numChildren()):
            child = node.Child(i)

            if isinstance(child, ClangVariableToken):
                high = child.getHighVariable()

                if high is not None and re.search("basic_.*stream", high.getDataType().getDisplayName()):
                    return True

        return False

    def cleanup(self):
        if self.clean is None:
            self.clean = ""

            while self.peek():
                if type(self.curr()) == ClangTokenGroup:
                    self.clean += IOParser(self.curr()).cleanup()
                elif self.__is_cxx_stl_io_stmt():
                    self.clean += self.__clean_cxx_stl_io_stmt_at_cursor()
                else:
                    self.clean += str(self.curr())

                self.next()

        return self.clean

if __name__ == "__main__":
    prog = FlatProgramAPI(currentProgram, monitor)
    decomp = FlatDecompilerAPI(prog)

    currentFunction = prog.getFunctionContaining(currentAddress)

    decomp.initialize()
    decompIfc = decomp.getDecompiler()

    cwd = os.path.dirname(os.path.realpath(__file__))

    functions = {}
    func = prog.getFirstFunction()

    while func:
        res = decompIfc.decompileFunction(func, 30, monitor)

        if res.decompileCompleted():
            namespace = func.getParentNamespace()
            fname = func.getName()
            clangAST = res.getCCodeMarkup()

            if namespace and not namespace.isGlobal():
                fname = "{}::{}".format(namespace.getName(True), fname)

            iop = IOParser(clangAST)

            functions[fname] = {
                "simpleName": func.getName(),
                "qualifiedNamespace": namespace.getName(True),
                "entry": func.getEntryPoint().toString(),
                "decompiled": res.getDecompiledFunction().getC(),
                "cleaned": iop.cleanup(),
                "nop": is_no_op_function(clangAST)
            }

        func = prog.getFunctionAfter(func)

    with open(os.path.join(cwd, "functions.json"), 'w') as funcFile:
        funcFile.write(json.dumps(functions))

    decomp.dispose()