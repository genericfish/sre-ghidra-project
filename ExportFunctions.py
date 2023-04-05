# Exports all functions in current program into "functions.json"

# @category: C3
# @author: Team 7.1

import os
import json

# https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
from ghidra.program.flatapi import FlatProgramAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html
from ghidra.app.decompiler import ClangStatement, ClangCommentToken, ClangNode

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

def extractStatements(node):
    if not isinstance(node, ClangStatement):
        stmts = []
        for i in range(node.numChildren()):
            child = node.Child(i)
            stmts += extractStatements(child)

        return stmts

    return [node]

def isNoOpFunction(node):
    stmts = extractStatements(node)

    return len(stmts) == 1

while func is not None:
    res = decompIfc.decompileFunction(func, 30, monitor)

    if res.decompileCompleted():
        namespace = func.getParentNamespace()
        fname = func.getName()
        if namespace is not None and not namespace.isGlobal():
            fname = "{}::{}".format(namespace.getName(True), fname)

        functions[fname] = {
            "simpleName": func.getName(),
            "entry": func.getEntryPoint().toString(),
            "decompiled": res.getDecompiledFunction().getC(),
            "nop": isNoOpFunction(res.getCCodeMarkup())
        }

    func = prog.getFunctionAfter(func)

with open(os.path.join(cwd, "functions.json"), 'w') as funcFile:
    funcFile.write(json.dumps(functions))

decomp.dispose()