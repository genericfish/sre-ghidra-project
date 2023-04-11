# Removes empty functions from the program.

# @category: C3
# @author: Team 7.1

import os
import json
import re

# https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
from ghidra.program.flatapi import FlatProgramAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html
from ghidra.app.decompiler import *

def extract_tokens(node, clang_token_types):
    # Get tokens from ClangTokenGroup AST matching types in clangTokens
    valid = any(map(lambda token: isinstance(node, token), clang_token_types))

    if not valid:
        tokens = []

        for i in range(node.numChildren()):
            child = node.Child(i)
            tokens += extract_tokens(child, clang_token_types)

        return tokens

    return [node]

def is_no_op_function(node):
    # Check if a given ClangTokenGroup effectively is a no-op and can be safely ignored
    # TODO: Figure out more ways a function is effectively useless from AST analysis
    stmts = extract_tokens(node, [ClangStatement])

    return len(stmts) == 1 and stmts[0].numChildren() == 1

if __name__ == "__main__":
    prog = FlatProgramAPI(currentProgram, monitor)
    decomp = FlatDecompilerAPI(prog)

    decomp.initialize()
    decompIfc = decomp.getDecompiler()

    cwd = os.path.dirname(os.path.realpath(__file__))

    functions = {}
    func = prog.getFirstFunction()

    numRemoved = 0
    while func:
        res = decompIfc.decompileFunction(func, 30, monitor)

        if res.decompileCompleted():
            clangAST = res.getCCodeMarkup()


            nextFunc = prog.getFunctionAfter(func)
            qualifiedNamespace = func.getParentNamespace().getName(True)
            if not func.isThunk() and not func.isExternal() and not re.search("<EXTERNAL>|__gnu_cxx|^std$", qualifiedNamespace) and is_no_op_function(clangAST) and not re.search("_fini$|register_tm_clones$", func.getName()):
                print("removing no-op function ({}) {} @ {}".format(qualifiedNamespace, func.getName(), func.getEntryPoint()))
                prog.removeFunction(func)
                numRemoved += 1

            func = nextFunc

    print("removed {} no-op functions.".format(numRemoved))

    decomp.dispose()