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
from ghidra.app.decompiler import ClangStatement

prog = FlatProgramAPI(currentProgram, monitor)
decomp = FlatDecompilerAPI(prog)

currentFunction = prog.getFunctionContaining(currentAddress)

decomp.initialize()
decompIfc = decomp.getDecompiler()

cwd = os.path.dirname(os.path.realpath(__file__))

functions = {}
func = prog.getFirstFunction()

while func is not None:
    res = decompIfc.decompileFunction(func, 30, monitor)

    if res.decompileCompleted():
        functions[func.getName()] = {
            "entry": func.getEntryPoint().toString(),
            "decompiled": res.getDecompiledFunction().getC()
        }

    func = prog.getFunctionAfter(func)

with open(os.path.join(cwd, "functions.json"), 'w') as funcFile:
    funcFile.write(json.dumps(functions))

decomp.dispose()