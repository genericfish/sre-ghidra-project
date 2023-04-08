# Finds C++ stream insertion/extraction operators and makes them more user friendly

# @category: C3
# @author: Team 7.1

import re
import sys

from ghidra.app.script import GhidraScript

# https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
from ghidra.program.flatapi import FlatProgramAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html
from ghidra.app.decompiler import *

#https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html
from ghidra.program.model.pcode import PcodeOp


def is_empty(node):
    # Check if ClangSyntaxToken is empty string or whitespace

    return isinstance(node, ClangSyntaxToken) and len(str(node).strip()) == 0


class Parser(object):
    # Simple LALR(n) parser

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


class IOParser(Parser):
    clean = None

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


    def __init__(self, root, skipEmpty=True, prog=None):
        if sys.version_info[0] <= 2:
            super(IOParser, self).__init__(root, skipEmpty, prog)
        else:
            super().__init__(root, skipEmpty, prog)


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

            ok = ok or self.multirematch(pattern) or self.multirematch(pattern2)

            n += 1

        if not ok:
            return False

        n = 0
        while not self.stmt_end(n):
            # Check to see if operating on std::cin/cout
            pattern = [
                [ClangSyntaxToken, "^std$", n],
                [ClangOpToken, "^::$", n + 1],
                [ClangVariableToken, "c[in|out]", n + 2]
            ]

            if self.multirematch(pattern):
                return True

            n += 1

        n = 0
        while not self.stmt_end(n):
            # Check to see if operating on std::basic_*stream
            pattern = [
                [ClangSyntaxToken, "^std$", n],
                [ClangOpToken, "^::$", n + 1],
                [ClangVariableToken, "basic_.*stream<.*>", n + 2]
            ]

            if self.multirematch(pattern):
                return True

            n += 1

        n = 0
        while not self.stmt_end(n):
            token = self.peek(n)
            if type(token) == ClangVariableToken:
                high = token.getHighVariable()

                if high and re.search("basic_.*stream", high.getDataType().getDisplayName()):
                    return True

            n += 1

        return False


    def cleanup(self):
        if self.clean is None:
            self.clean = ""

            while self.peek():
                if self.__is_cxx_stl_io_stmt():
                    n = 0
                    found=""
                    while self.peek(n) and type(self.peek(n)) != ClangBreak:
                        found += str(self.peek(n))
                        n += 1

                    if self.prog:
                        cleanIO = self.__clean_cxx_stl_io_stmt_at_cursor()
                        cleanStr = "".join(cleanIO).strip()
                        addr = self.curr().getMinAddress()

                        print("found operator{} @ {} : {}".format(cleanIO[2], addr, cleanStr))
                        preComment = self.prog.getPreComment(addr)
                        if not preComment or not cleanStr in preComment:
                            self.prog.setPreComment(addr, cleanStr)

                    while self.peek() and type(self.peek()) != ClangBreak:
                        self.next()

                self.next()


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

        res = decompIfc.decompileFunction(currentFunction, 30, monitor)

        if res.decompileCompleted():
            clangAST = res.getCCodeMarkup()
            iop = IOParser(clangAST, skipEmpty=True, prog=prog)
            iop.cleanup()

        decomp.dispose()

    cleanup()