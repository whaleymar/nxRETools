#!/bin/python3

# NOT A GHIDRA SCRIPT -- CALLS THE HEADLESS ANALYZER
# recursively goes through ghidra projects in parent project folder
# and saves them to .gzf archives

import subprocess
import pathlib as path
import sys
import os

def getGhidraProjectName(projectDirectory:path.Path):
    # does anyone use more than one directory in a project?
    for file in projectDirectory.glob("**/*"):
        if file.suffix == ".gpr":
            return file.stem
    
    return ""

def archiveProject(ghidraPath, ghidraProjectName, projectDirectory, scriptsPath):
    headlessScript = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    headlessCmd = path.PurePath(ghidraPath, "support", headlessScript)
    command = [
        str(headlessCmd),
        str(projectDirectory),
        ghidraProjectName,
        "-noanalysis",
        "-scriptPath",
        str(scriptsPath),
        "-postScript",
        "ExportToGZF.py",
        ghidraProjectName, # folder where project files are stored
        "-process",
        "-recursive",
        "-readOnly"
    ]
    # print(" ".join(command))
    subprocess.run(command)

    return True

def main(ghidraPath, projectParentDirectory, scriptsPath):
    # if parent directory is a project directory, archive that one
    ghidraProjectName = getGhidraProjectName(projectParentDirectory)
    if ghidraProjectName:
        saved = archiveProject(ghidraPath, ghidraProjectName, projectParentDirectory, scriptsPath)
        return

    for projectDirectory in path.Path(projectParentDirectory).glob("**/*"):
        if not projectDirectory.is_dir():
            continue
        ghidraProjectName = getGhidraProjectName(projectDirectory)
        if ghidraProjectName:
            saved = archiveProject(ghidraPath, ghidraProjectName, projectDirectory, scriptsPath)

if __name__ == "__main__":
    import sys
    ghidraPath, projectParentDirectory, scriptsPath = sys.argv[1:4]
    main(ghidraPath, projectParentDirectory, scriptsPath)