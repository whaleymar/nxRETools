import os

from ghidra.app.script import GhidraScript
from java.io import File


def main():
    prog = getCurrentProgram()

    args = getScriptArgs()
    if len(args) != 1:
        print("expected 1 arg: destination path")
        print(args)
        return

    destinationPath = args[0]
    if not os.path.exists(destinationPath):
        os.makedirs(destinationPath)

    df = prog.getDomainFile()
    outPath = os.path.join(destinationPath, prog.getName()) + ".gzf"
    outfile = File(outPath)
    df.packFile(outfile, monitor)


main()
