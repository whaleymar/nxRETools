#!/bin/python3

# usage: 
# 1. run nx2elf on executable (e.g. `main`)
# 2. run `readelf -s main.elf | getSyms.py main`

# arguments:
# 1. name of executable

import sys

def formatLine(l, fileName):
    split = l.split()
    try:
        if split[6] == "UND" or split[3] != "FUNC":
            return ""
        return f"{split[7]} = __{fileName}_start + 0x{split[1]};"
    
    except IndexError:
        return ""

def parseSyms(stdin:list, fileName):
    out = []
    for line in stdin:
        newLine = formatLine(line, fileName)
        if newLine:
            out.append(newLine)
    return out


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise ValueError("Expected 1 arg")
    for line in parseSyms(sys.stdin.readlines(), sys.argv[1]):
        print(line)