# Renames variables to a simpler form
#
# # @category: C3
# # @author: Team 7.1
#
import re

# https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
from ghidra.program.flatapi import FlatProgramAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

# # https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html
from ghidra.app.decompiler import *

# https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/package-summary.html
from ghidra.program.model.pcode import *

# https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/package-summary.html
from ghidra.program.model.data import *

# https://ghidra.re/ghidra_docs/api/ghidra/program/database/package-summary.html
from ghidra.program.database import *

# https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/Symbol.html
from ghidra.program.model.symbol import SourceType, SymbolType

# https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/package-summary.html
from ghidra.program.model.listing import *




# variable and parameter renaming function
def rename():
    # initialization
    prog = FlatProgramAPI(currentProgram, monitor)
    decomp = FlatDecompilerAPI(prog)
    currentFunction = prog.getFirstFunction()
    if currentFunction is None:
        print("Error: No function found at address " + str(currentAddress))
        exit()

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

# Call the function to automatically rename all variables in current Program
rename()