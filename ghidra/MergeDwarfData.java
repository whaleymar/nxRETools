//
//@author whaley
//@category DWARF
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.app.util.bin.format.dwarf4.next.DWARFImportOptions;
import ghidra.app.util.bin.format.dwarf4.next.DWARFParser;
import ghidra.app.util.bin.format.dwarf4.next.DWARFImportSummary;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;

public class MergeDwarfData extends GhidraScript {
	@Override
	public void run() throws Exception {
		
		File dwarfBuild = askFile("Choose executable", "Ok");
		boolean replaceAll = askYesNo("Options", "Replace defined structs?");
		
		ArrayList<Structure> dwarfStructs = getDwarfInfo(dwarfBuild);
		if (dwarfStructs == null) return;
		println("Num structs found in DWARF info: " + Integer.toString(dwarfStructs.size()));
		
		ProgramBasedDataTypeManager dataManager = currentProgram.getDataTypeManager();
		HashMap<String, Structure> mainStructs = getMainStructs(dataManager);
		mergeDwarfStructs(dataManager, mainStructs, dwarfStructs, replaceAll);
	}
	
	public ArrayList<Structure> getDwarfInfo(File dwarfBuild) throws Exception {
		
		Program dwarfProgram = importFile(dwarfBuild);
		int transID = dwarfProgram.getDataTypeManager().startTransaction("reading data");
		ArrayList<Structure> dwarfStructs = readDwarfProgram(dwarfProgram);
		dwarfProgram.getDataTypeManager().endTransaction(transID, false);
		return dwarfStructs;
		
	}
	
	public ArrayList<Structure> readDwarfProgram(Program dwarfProgram) throws Exception {
		if (!DWARFProgram.isDWARF(dwarfProgram)) {
			popup("Unable to find DWARF information, aborting");
			return null;
		}
		DWARFImportOptions importOptions = new DWARFImportOptions();
		
		// skipping functions for now
		importOptions.setCreateFuncSignatures(false);
		importOptions.setImportFuncs(false);
		
		importOptions.setOrganizeTypesBySourceFile(false);

		importOptions.setImportLimitDIECount(Integer.MAX_VALUE);
		try (DWARFProgram dwarfProg = new DWARFProgram(dwarfProgram, importOptions, monitor)) {
			DWARFParser dp = new DWARFParser(dwarfProg, monitor);
			DWARFImportSummary importSummary = dp.parse();
			importSummary.logSummaryResults();
			
			ProgramBasedDataTypeManager dataManager = dwarfProgram.getDataTypeManager();
			
			Iterator<Structure> structIter = dataManager.getAllStructures();
			ArrayList<Structure> dwarfStructs = new ArrayList<Structure>();
			structIter.forEachRemaining(dwarfStructs::add);
			
			return dwarfStructs;
		}
	}
	
	public String getStructParent(String structPath) {
		return structPath.split("/")[1];
	}
	
	public HashMap<String, Structure> getMainStructs(ProgramBasedDataTypeManager dataManager) {
		HashMap<String, Structure> mainStructs = new HashMap<String, Structure>();
		Iterator<Structure> structIter = dataManager.getAllStructures();
		
		while (structIter.hasNext()) {
			Structure struct = structIter.next();
			
			String archiveName = struct.getSourceArchive().getName();			
			if (!archiveName.equals("main")) continue;
			
			String structName = struct.getName();
			mainStructs.put(structName, struct);	
		}
		
		return mainStructs;
	}
	
	public void mergeDwarfStructs(ProgramBasedDataTypeManager dataManager, HashMap<String, Structure> mainStructs, ArrayList<Structure> dwarfStructs, boolean replaceAll) {
		DataTypeConflictHandler conflictHandler = null;
		
		int replaced=0;
		int added=0;
		for (int i=0; i<dwarfStructs.size(); i++) {
			Structure struct = dwarfStructs.get(i);
			
			String structName = struct.getName();
			if (mainStructs.containsKey(structName)) {
				Structure ogStruct = mainStructs.get(structName);
				
				if (!replaceAll && !ogStruct.isNotYetDefined()) continue;
				else if (ogStruct.isNotYetDefined()) ogStruct.setDescription("");
				
				ogStruct.replaceWith(struct);
				replaced++;
//				println("Replaced struct: " + structName); // DEBUG
			}
			else {
				dataManager.addDataType(struct, conflictHandler);
				added++;
//				println("Added new struct: " + structName); // DEBUG
			}
		}
		
		println("Added " + Integer.toString(added) + " structs");
		println("Replaced " + Integer.toString(replaced) + " structs");
	}
}