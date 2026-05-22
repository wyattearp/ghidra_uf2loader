import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class VerifyUF2Import extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        MemoryBlock[] blocks = mem.getBlocks();
        
        println("Number of memory blocks: " + blocks.length);
        
        boolean foundFlash = false;
        for (MemoryBlock block : blocks) {
            println("Block: " + block.getName() + " [" + block.getStart() + " - " + block.getEnd() + "]");
            if (block.getStart().getOffset() == 0x10000000L) {
                foundFlash = true;
            }
        }
        
        if (foundFlash) {
            println("VERIFICATION_SUCCESS: Found flash block at 0x10000000");
        } else {
            println("VERIFICATION_FAILURE: No block found at 0x10000000");
        }

        AddressIterator entryPoints = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        if (entryPoints.hasNext()) {
            println("Found entry point at: " + entryPoints.next());
            println("VERIFICATION_SUCCESS: Entry point detected");
        } else {
            println("VERIFICATION_FAILURE: No entry point detected");
        }
    }
}
