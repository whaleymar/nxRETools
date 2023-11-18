# credit: fruityloops

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol.SourceType import *
from ghidra.util.exception import *
from ghidra.app.util import NamespaceUtils
import csv
import re

addressBase = 0x7100000000

currentProgram = getCurrentProgram()
functionManager = currentProgram.getFunctionManager()
namespaceManager = currentProgram.getNamespaceManager()
symbolTable = currentProgram.getSymbolTable()

def splitNamespace(symbol):
    namespaces = []
    bracket_level = 0
    current = ''
    i = 0
    for c in symbol:
        if c == '<':
            bracket_level += 1
            current += c
        elif c == '>':
            bracket_level -= 1
            current += c
        elif c == ':' and symbol[i] == ':' and bracket_level == 0:
            if current != '':
                namespaces.append(current)
            current = ''
        else:
            current += c
        i += 1
    namespaces.append(current)
    return namespaces

with open(askFile("Open Symbol Map", "Open").getAbsolutePath(), 'r') as csvfile:
    reader = csv.reader(csvfile)
    isFirstRow = True
    for row in reader:
        if isFirstRow:
            isFirstRow = False
            continue
        addr = int(row[0], 16)
        symbol = row[1]
        doContinue = False
        deleteAllAtCurrent = False
        ghidraAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addressBase + addr)
        syms = symbolTable.getSymbols(ghidraAddr)
        
        if "_Z" in symbol:
            for foundSymbol in syms:
                if foundSymbol.getName() == symbol and len(syms) < 3:
                    doContinue = True
                    break
                else:
                    deleteAllAtCurrent = True
            if doContinue:
                continue
            if deleteAllAtCurrent:
                for foundSymbol in syms:
                    foundSymbol.delete()
            symRef = createLabel(ghidraAddr, symbol, namespaceManager.getGlobalNamespace(), True, IMPORTED)
        elif "::" not in symbol:
            for foundSymbol in syms:
                if foundSymbol.getName() == symbol:
                    doContinue = True
            if doContinue:
                continue
            symRef = createLabel(ghidraAddr, symbol, namespaceManager.getGlobalNamespace(), True, IMPORTED)
        else:
            namespaces = splitNamespace(symbol)
            symbolName = namespaces[-1]
            namespaces = namespaces[:-1]
            parentNamespace = ""
            for namespace in namespaces:
                parentNamespace += namespace + '::'
            parentNamespace = parentNamespace[:-2]
            ghidraNamespace = NamespaceUtils.createNamespaceHierarchy(parentNamespace, namespaceManager.getGlobalNamespace(), currentProgram, IMPORTED)
            for foundSymbol in syms:
                if foundSymbol.getName() == symbolName and foundSymbol.getParentNamespace() == ghidraNamespace:
                    doContinue = True
                    break
            else:
                print("Deleting " + str(foundSymbol.getParentNamespace()) + "::" + foundSymbol.getName())
                foundSymbol.delete()
            if doContinue:
                continue
            print("Adding " + symbol + " at " + str(ghidraAddr.getOffset()))
            symRef = createLabel(ghidraAddr, symbolName, ghidraNamespace, True, IMPORTED)
            