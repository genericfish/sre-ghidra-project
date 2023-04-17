# Incorporates CleanIO.py, ControlFlow.py, RemovEmptyFunctions.py, and Rename.py

# @category: C3
# @author: Team 7.1

import os
import json
import re
import sys
import subprocess
import time

from ghidra.app.script import GhidraScript

# https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
from ghidra.program.flatapi import FlatProgramAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html
from ghidra.app.decompiler import *

from ghidra.program.model.listing import VariableFilter

from ghidra.program.model.pcode import *

# https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/package-summary.html
from ghidra.program.model.data import *

# https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Symbol.html
from ghidra.program.model.symbol import SourceType, SymbolType

def is_empty(node):
    # Check if ClangSyntaxToken is empty string or whitespace

    return isinstance(node, ClangSyntaxToken) and len(str(node).strip()) == 0


class Parser(object):
    # Simple LL(n) parser
    def __init__(self, root, skipEmpty=False, prog=None):
        self.root = root
        self.prog = prog
        self.skipEmpty = skipEmpty
        self.cursor = 0

        assert type(root) in [ClangTokenGroup, ClangFunction]

        # Given a ClangNode AST flatten into linear token stream
        self.tokens = []
        root.flatten(self.tokens)

        if skipEmpty:
            self.tokens = filter(lambda x: not is_empty(x) and not type(x) == ClangCommentToken, self.tokens)


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

    def match(self, tokval, strval, n=0):
        token = self.peek(n)

        if strval:
            return type(token) == tokval and str(token) == strval

        return type(token) == tokval


    def rematch(self, tokval, reval, n=0):
        token = self.peek(n)

        if reval:
            return type(token) == tokval and re.search(reval, str(token))

        return type(token) == tokval


    def multimatch(self, matches):
        return all(self.match(*match) for match in matches)


    def multirematch(self, matches):
        return all(self.rematch(*match) for match in matches)


    def stmt_end(self, n=0):
        return not self.peek(n) or self.rematch(ClangSyntaxToken, ';|{|}', n)


class IOParser(Parser):
    stringTable = None


    def __init__(self, root, skipEmpty=True, prog=None, stringTable=None):
        if sys.version_info[0] <= 2:
            super(IOParser, self).__init__(root, skipEmpty, prog)
        else:
            super().__init__(root, skipEmpty, prog)

        self.stringTable = stringTable


    def __clean_cxx_stl_io_stmt_at_cursor(self):
        assignment = ""
        value = ""
        operation = None
        stream = None

        while not self.stmt_end():
            pattern = [
                [ClangSyntaxToken, "^std", 0],
                [ClangOpToken, "^::", 1],
                [ClangFuncNameToken, "operator[<<|>>]", 2]
            ]

            if self.multirematch(pattern):
                operation = re.sub("operator", "", str(self.peek(2)))
                self.next(3)
                continue

            pattern = [
                [ClangSyntaxToken, "^std", 0],
                [ClangOpToken, "^::", 1],
                [ClangSyntaxToken, "^basic_.*stream<.*>", 2],
                [ClangOpToken, "^::", 3],
                [ClangFuncNameToken, "^operator[<<|>>]", 4]
            ]

            if self.multirematch(pattern):
                operation = re.sub("operator", "", str(self.peek(4)))
                self.next(5)
                continue

            if not operation:
                assignment += str(self.curr())

            if stream and type(self.curr()) == ClangVariableToken:
                value = str(self.curr())

                if self.curr().getPcodeOp().getInputs()[-1] in self.stringTable:
                    print("found in stable {}".format(self.curr()))

                if re.search("PTR_endl<.*>", value):
                    value = "std::endl"

                break
            elif operation:
                pattern = [
                    [ClangSyntaxToken, "^std", 0],
                    [ClangOpToken, "^::", 1],
                    [ClangVariableToken, None, 2]
                ]

                if self.multirematch(pattern):
                    stream = str(self.curr()) + str(self.peek()) + str(self.peek(2))
                    self.next(3)
                    continue

                if type(self.curr()) == ClangVariableToken:
                    stream = str(self.curr())

            self.next()

        return (assignment, stream, operation, value)


    def __is_cxx_stl_io_stmt(self):
        n = 0
        ok = False
        while not self.stmt_end(n):
            # Look for calls to std::operator[<<|>>]
            pattern = [
                [ClangSyntaxToken, "^std", n],
                [ClangOpToken, "^::", n + 1],
                [ClangFuncNameToken, "operator[<<|>>]", n + 2]
            ]

            pattern2 = [
                [ClangSyntaxToken, "^std", n],
                [ClangOpToken, "^::", n + 1],
                [ClangSyntaxToken, "^basic_.*stream<.*>", n + 2],
                [ClangOpToken, "^::", n + 3],
                [ClangFuncNameToken, "^operator[<<|>>]", n + 4]
            ]

            if self.multirematch(pattern) or self.multirematch(pattern2):
                ok = True
                break

            n += 1

        if not ok:
            return False

        n = 0
        while not self.stmt_end(n):
            # Check to see if operating on std::cin/cout
            pattern = [
                [ClangSyntaxToken, "^std$", n],
                [ClangOpToken, "^::$", n + 1],
                [ClangVariableToken, "c[in|out]|basic_.*stream<.*>", n + 2]
            ]

            if self.multirematch(pattern):
                return True

            n += 1

        n = 0
        while not self.stmt_end(n):
            # Check to see if operating on variable type of basic_.*stream
            token = self.peek(n)
            if type(token) == ClangVariableToken:
                high = token.getHighVariable()

                if high and re.search("basic_.*stream", high.getDataType().getDisplayName()):
                    return True

            n += 1

        return False


    def cleanup(self):
        while self.peek():
            if self.__is_cxx_stl_io_stmt():
                if self.prog:
                    cleanIO = self.__clean_cxx_stl_io_stmt_at_cursor()
                    cleanStr = "".join(cleanIO).strip()
                    addr = self.curr().getMinAddress()

                    print("found operator{} @ {} : {}".format(cleanIO[2], addr, cleanStr))
                    preComment = self.prog.getPreComment(addr)
                    comment = cleanStr

                    if preComment and not cleanStr in preComment:
                        comment = preComment + "\n\n" + comment

                    self.prog.setPreComment(addr, comment)

                while self.peek() and not self.stmt_end():
                    self.next()

            self.next()

        self.seek(0)
        while self.peek():
            token = self.curr()
            if type(token) == ClangVariableToken:
                pcode = token.getPcodeOp()

                if pcode and pcode.getOpcode() == PcodeOp.PTRSUB:
                    vaddr = pcode.getInputs()[-1].getOffset()

                    if vaddr in self.stringTable:
                        addr = self.curr().getMinAddress()
                        comment = "var: {} -> str: {}".format(self.curr(), self.stringTable[vaddr])
                        preComment = self.prog.getPreComment(addr)

                        if preComment and not comment in preComment:
                            comment = preComment + "\n\n" + comment

                        self.prog.setPreComment(addr, comment)
            self.next()


def create_string_table(prog, decompIfc):
    '''
    Creates an address to c-string lookup table based off of static strings
    found inside the library
    '''

    initFunction = prog.getGlobalFunctions("__static_initialization_and_destruction_0")[0]

    # Did not find any static initializations
    if not initFunction:
        return

    res = decompIfc.decompileFunction(initFunction, 30, monitor)

    stringTable = {}

    blocks = prog.getMemoryBlocks()
    addrFactory = prog.getAddressFactory()
    rodata = None
    ramID = None

    for b in blocks:
        if b.getName() == '.rodata':
            ramID = b.getStart().getAddressSpace().getSpaceID()
            rodata = b
            space = b.getStart().getAddressSpace()
            print("found rodata: start: {} end: {} loaded: {} address space: {} ({})"
                  .format(b.getStart(), b.getEnd(), b.isLoaded(), space.getName(), space.getSpaceID()))

    if res.decompileCompleted():
        clangAST = res.getCCodeMarkup()
        parser = Parser(clangAST, skipEmpty=True, prog=prog)

        stringAllocLocations = {}
        while parser.peek():
            # Assumption: Matched string constructor
            #     Format: basic_string(stack_location, data_location)
            if parser.match(ClangFuncNameToken, "basic_string"):
                stackToken = None

                while not parser.stmt_end():
                    token = parser.curr()

                    if type(token) == ClangVariableToken:
                        if stackToken is not None:
                            stringAllocLocations[str(stackToken)] = {
                                "stack": stackToken,
                                "data": token
                            }
                        else:
                            stackToken = token

                    parser.next()
            parser.next()

        for v in stringAllocLocations.values():
            stackAddress = v["stack"].getPcodeOp().getInputs()[-1]
            data = v["data"]

            high = data.getHighVariable()
            if high and type(high) == HighConstant:
                stringTable[stackAddress.getOffset()] = str(data);

            # Assert that we have a PTRSUB PcodeOp
            pcode = data.getPcodeOp()
            if not pcode or pcode.getOpcode() != PcodeOp.PTRSUB:
                continue

            # PcodeOp PTRSUB has inputs (val, address), we want the address
            address = pcode.getInputs()[-1].getAddress()

            # For some reason the addresses we get here from PCode Varnodes do not belong to the correct address space
            if not address.isConstantAddress():
                continue

            # Convert const: address into RAM address within .RODATA address space
            raddr = addrFactory.getAddress(ramID, address.getOffset())
            byte = prog.getByte(raddr)
            foundString = ""

            # Assumption: ascii null-terminated string starts at the const address
            while rodata.contains(raddr) and byte != 0:
                foundString += chr(byte)
                raddr = raddr.next()
                byte = prog.getByte(raddr)

            stringTable[stackAddress.getOffset()] = "\"{}\"".format(foundString)

    return stringTable



#THE NEXT TWO FUNCTIONS ARE USED FOR THE REMOVE_EMPTY_FUNCS PART OF THE SCRIPT
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
    stmts = extract_tokens(node, [ClangStatement])

    return len(stmts) == 1 and stmts[0].numChildren() == 1



#THIS BLCOK OF CODE IS USED FOR THE ControlFlow SCRIPT
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



#THIS BLOCK OF CODE HAS THE DEFINITIONS FOR THE MAIN PARTS OF OUR SCRIPTS. THESE PARTS USE THE ABOVE CLASSES AND FUNCTIONS
if __name__ == "__main__":
    prog = FlatProgramAPI(currentProgram, monitor)
    decomp = FlatDecompilerAPI(prog)



    def cleanup_IO():
        currentFunction = prog.getFunctionContaining(currentAddress)

        if not currentFunction:
            print("PLEASE OPEN A FUNCTION TO CLEAN STREAM OPERATIONS")
            return

        print("CLEANING STREAM OPERATIONS IN FUNCTION {} AT ADRESS {}".format(currentFunction.getName(), currentFunction.getEntryPoint()))
        decomp.initialize()
        decompIfc = decomp.getDecompiler()

        stringTable = create_string_table(prog, decompIfc)
        res = decompIfc.decompileFunction(currentFunction, 30, monitor)

        if res.decompileCompleted():
            clangAST = res.getCCodeMarkup()
            iop = IOParser(clangAST, skipEmpty=True, prog=prog, stringTable=stringTable)
            iop.cleanup()

        
    def remove_empty_funcs():
        print("REMOVING NO-OP FUNCTIONS")
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

    
    def rename_types():
        # initialization
        print("RENAMING STRINGS AND VARIABLE NAMES")
        currentFunction = prog.getFirstFunction()
        if currentFunction is None:
            print("PLEASE OPEN A FUNCTION TO RENAME TYPES")
            return

        while not currentFunction is None:
            decomp.initialize()
            decompIfc = decomp.getDecompiler()
            res = decompIfc.decompileFunction(currentFunction, 30, monitor)

            # for renaming the non-auto parameters
            func = res.getFunction()
            params = func.getParameters()

            # renaming params
            for j, param in enumerate(params):
                if not param.isAutoParameter():
                    #get name of data type and cleanup
                    newName = re.sub('[^\w]', "", param.getDataType().getName().replace("basic_string<char,std::char_traits<char>,std::allocator<char>>", "std_string"))
                    param.setName("{}_{}".format(newName, param.getName()), param.getSource())

            # for getting the symbols to rename the variables
            high_func = res.getHighFunction()
            lsm = high_func.getLocalSymbolMap()
            symbols = lsm.getSymbols()

            # for renaming the variables
            hfdbu = HighFunctionDBUtil()
            for i, symbol in enumerate(symbols):
                if not symbol.isParameter():
                    #get name of data type and cleanup
                    newName = re.sub('[^\w]', '', symbol.getDataType().getName().replace("basic_string<char,std::char_traits<char>,std::allocator<char>>", "std_string"))
                    try: 
                        hfdbu.updateDBVariable(symbol, "{}_{}".format(newName, i+1), None, SourceType.USER_DEFINED)
                    except: 
                        print("DUPLICATE VARIABLE NAME ENCOUNTERED: This is likely due to re-running this script or the rename.py script.")
                        return

            currentFunction = prog.getFunctionAfter(currentFunction)
    
    
    def control_flow():
        print("PRINTING THE CONTROL FLOW, SENDING REVERSED CODE TO A FILE")
        location = os.path.dirname(os.path.realpath(__file__)) + "\\"
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
    


    #CALLS THE FUNCTIONS DEFINED ABOVE, WHICH ARE THE MAJOR SCRIPTS WE DEVELOPED, JUST COMBINED
    remove_empty_funcs()
    print('\n\n')
    cleanup_IO()
    print('\n\n')
    rename_types()
    print('\n\n')
    control_flow()
    decomp.dispose()