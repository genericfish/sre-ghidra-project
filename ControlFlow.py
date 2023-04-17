# Prints the control flow of the program, starting from main

# @category: C3
# @author: Team 7.1

import os
import re
import sys
import subprocess
import time


# Make the nodes in the BFS control flow algorithm have a visited option
# That way it will be resistant to recursion

from ghidra.app.script import GhidraScript

# https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
from ghidra.program.flatapi import FlatProgramAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html
from ghidra.app.decompiler import *

from ghidra.program.model.listing import VariableFilter

from ghidra.program.model.pcode import *

location = os.path.dirname(os.path.realpath(__file__)) + "\\"

def getListOfFunctions():
    listofFuncs =[]
    function = getFirstFunction()
    while function is not None:
        listofFuncs.append(str(function.getName()))
        function_address = function.getEntryPoint()
        function = getFunctionAfter(function)
        
    return listofFuncs

def FunctionsAddressDict():
    funcDict = {}
    function = getFirstFunction()
    while function is not None:
        functionName = str(function.getName())
        functionAddress = function.getEntryPoint()
        funcDict[functionName] = functionAddress
        function = getFunctionAfter(function)
    return funcDict

def FunctionsVisitedDict():
    funcDict = {}
    function = getFirstFunction()
    while function is not None:
        functionName = str(function.getName())
        funcDict[functionName] = 0 # Where zero represents not visited 
        function = getFunctionAfter(function)
    return funcDict

def decompiledCurrentFunctionString(funcString=""):
    prog = FlatProgramAPI(currentProgram, monitor)
    decomp = FlatDecompilerAPI(prog)

    currentFunction = prog.getFunctionContaining(currentAddress)
    
    if funcString != "":
        funcAddressDict = FunctionsAddressDict()
        funcAddress = funcAddressDict[funcString]
        currentFunction = prog.getFunctionContaining(funcAddress)
        
    if currentFunction is None:
        print("Error: No function found at address " + str(currentAddress))
        exit()
        
    decomp.initialize()
    decompIfc = decomp.getDecompiler()

    DecompiledFunction = decompIfc.decompileFunction(currentFunction, 30, monitor)
    
    if DecompiledFunction.decompileCompleted():
        DecompiledString = str(DecompiledFunction.getCCodeMarkup())
        decomp.dispose()
        return DecompiledString
    else:
        decomp.dispose()
        return "ERROR"

def getCalledFuncsNamesInDecompiledCode(funcStr):
    patternFull = r'\b\w+\s*\([^)]*\);'
    matchesFull = re.findall(patternFull, funcStr)
    patternName = r'\b(\w+)\s*\([^)]*\);'
    matchesName = re.findall(patternName, funcStr)
    
    verifiedMatchesName = []
    listOfFunctions = getListOfFunctions()
    
    cominedList = zip(matchesFull, matchesName)
    VerfiedCombined = []
    for funcNames in cominedList:
        if funcNames[1] in listOfFunctions:
            verifiedMatchesName.append(funcNames[1])
            VerfiedCombined.append(funcNames)

    return [VerfiedCombined, verifiedMatchesName]
    

def getFunctionFlow(DecompiledFuncStr, depth, visitedDict):
    
    while len(getCalledFuncsNamesInDecompiledCode(DecompiledFuncStr)[1]) > 0:
        for calledFuncName in getCalledFuncsNamesInDecompiledCode(DecompiledFuncStr)[0]:
            
            DecompiledFuncStr = decompiledCurrentFunctionString(calledFuncName[1])
            if visitedDict[calledFuncName[1]] == 0:
                visitedDict[calledFuncName[1]] = 1
                getFunctionFlow(DecompiledFuncStr,depth+1, visitedDict)
                print(depth*'-' + calledFuncName[0])
            else:
                return


# This will write the decompiled function to a string and clean it up with clang, Will prob use for C4
with open(location + 'temp.cpp', 'w') as f:
    f.write(decompiledCurrentFunctionString())
    subprocess.Popen("clang-format " + location + 'temp.cpp > ' + location + 'temp.cpp', shell=True) 
    f.write("\n/*\nrun: ./fuzz\n*/")
    subprocess.Popen("code " + location, shell=True)     

# Print my control Flow, Will prob use this in conjunction with the write decompiled file above for a
# clickable HTML map that will display the program when clicked
prog = FlatProgramAPI(currentProgram, monitor)
decomp = FlatDecompilerAPI(prog)
currentFunction = prog.getFunctionContaining(currentAddress)
print(str(currentFunction)) 
DecompiledFuncStr = decompiledCurrentFunctionString()
depth = 1
visitedDict = FunctionsVisitedDict()
getFunctionFlow(DecompiledFuncStr, depth, visitedDict)


