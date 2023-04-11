# Finds C++ stream insertion/extraction operators and makes them more user friendly

# @category: C3
# @author: Team 7.1

import os
import re
import sys

from ghidra.app.script import GhidraScript

# https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
from ghidra.program.flatapi import FlatProgramAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html
from ghidra.app.decompiler import *

from ghidra.program.model.listing import VariableFilter

from ghidra.program.model.pcode import *

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


if __name__ == "__main__":
    prog = FlatProgramAPI(currentProgram, monitor)
    decomp = FlatDecompilerAPI(prog)

    def cleanup():
        currentFunction = prog.getFunctionContaining(currentAddress)

        if not currentFunction:
            print("[C3] No function containing current address.")
            return

        print("[C3] Cleaning stream operations in {} @ {}".format(currentFunction.getName(), currentFunction.getEntryPoint()))
        decomp.initialize()
        decompIfc = decomp.getDecompiler()

        stringTable = create_string_table(prog, decompIfc)

        res = decompIfc.decompileFunction(currentFunction, 30, monitor)

        if res.decompileCompleted():
            clangAST = res.getCCodeMarkup()
            iop = IOParser(clangAST, skipEmpty=True, prog=prog, stringTable=stringTable)
            iop.cleanup()

        decomp.dispose()

    cleanup()