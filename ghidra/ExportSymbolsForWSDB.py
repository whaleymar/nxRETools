# credit: fruityloops

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import GhidraScript

addressBase = 0x7100000000

def getSymbols():
    currentProgram = getCurrentProgram()
    symbolTable = currentProgram.getSymbolTable()
    symbols = symbolTable.getAllSymbols(False)

    outSyms = {}

    for symbol in symbols:
        symbolName = symbol.getName()
        symbolAddress = symbol.getAddress()
        namespace = symbol.getParentNamespace()
        namespace = str(namespace).replace(" (GhidraClass)", "")
        if "<EXTERNAL>" in namespace or "FUN_71" in symbolName or "switchD" in namespace or "LAB_71" in symbolName:
            continue

        if symbolAddress.getOffset() <= addressBase:
            continue

        if namespace == "Global":
            symbolOut = symbolName
        else:
            symbolOut = namespace + "::" + symbolName

        if symbolOut == "end":
            continue

        function = getFunctionAt(symbolAddress)
        if function is not None and function.isThunk():
            continue

        if symbolAddress in outSyms:
            if "_Z" not in outSyms[symbolAddress] and "_Z" in symbolName:
                outSyms[symbolAddress] = symbolOut
        else:
            outSyms[symbolAddress] = symbolOut
    return outSyms

with open(askFile("Save Symbol Map", "Save").getAbsolutePath(), 'w') as f:
    symbols = getSymbols()
    f.write('"Address","Name","Last Updated","Last Updated User"')
    for address, symbol in symbols.items():
        f.write('\n')
        symbolSanitized = symbol.replace('"', '""')
        f.write('"' + format(address.getOffset() - addressBase, "08X") + '","' + symbolSanitized + '","0","0"')
