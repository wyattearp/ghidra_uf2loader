/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package uf2loader;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This is a loader to make loading UF2 files a little easier.
 * 
 * See https://github.com/microsoft/uf2
 */
public class uf2loaderLoader extends AbstractLibrarySupportLoader {
	public static final long UF2_BLOCK_SIZE = 0x200;
	public static final long UF2_FIRST_MAGIC = 0x0A324655;
	public static final long UF2_SECOND_MAGIC = 0x9E5D5157;
	public static final long UF2_FINAL_MAGIC = 0x0AB16F30;
	public static final long UF2_DATA_BLOCK_SIZE = 0x1dc; // 476
	
	/*
	 * struct UF2_Block {
		    // 32 byte header
		    uint32_t magicStart0;
		    uint32_t magicStart1;
		    uint32_t flags;
		    uint32_t targetAddr;
		    uint32_t payloadSize;
		    uint32_t blockNo;
		    uint32_t numBlocks;
		    uint32_t fileSize; // or familyID;
		    uint8_t data[476];
		    uint32_t magicEnd;
		} UF2_Block;
	 */
    private long m_magicStart0;
    private long m_magicStart1;
    private long m_flags;
    private long m_targetAddr;
    private long m_payloadSize;
    private long m_blockNo;
    private long m_numBlocks;
    private long m_fileSize; // or familyID;
    @SuppressWarnings("unused")
	private byte m_data[];   // 476
    private long m_magicEnd;

	@Override
	public String getName() {

		// Name the loader.  This name must match the name of the loader in the .opinion 
		// files.
		return "uf2loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		// if we get the things we need, we'll load it
		int shouldLoad = 0;
		
		if (provider.length() < UF2_BLOCK_SIZE) {
			return loadSpecs;
		}
		
		BinaryReader br = new BinaryReader(provider, true);
		
		// it's such a small thing, just read all of it and we'll sort it out later
		populateBlock(br, 0);
	    
	    // check to see if things were sane
	    if (Long.compareUnsigned(m_magicStart0, UF2_FIRST_MAGIC) == 0) {
	    	Msg.info(this, "first magic matches");
	    	shouldLoad++;
	    }
	    
	    if (Long.compareUnsigned(m_magicStart1, UF2_SECOND_MAGIC) == 0) {
	    	Msg.info(this, "second magic matches");
	    	shouldLoad++;
	    }
	    
	    if (Long.compareUnsigned(m_magicEnd, UF2_FINAL_MAGIC) == 0) {
	    	Msg.info(this, "final magic matches");
	    	shouldLoad++;
	    }
	    
	    if (shouldLoad > 0) {
	    	Msg.info(this, "UF2 loader can try to load this");
	    	// TODO: there's a JSON file that can make better recommendations based on the familyID if set
	    	loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:Cortex", "default"), true));
	    }
	    
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		BinaryReader br = new BinaryReader(provider, true);
		InputStream in = provider.getInputStream(0);
		Memory mem = program.getMemory();
		br.setPointerIndex(0);
		
		long num_blocks = provider.length();
		var addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		
		for (long blockNumber = 0; blockNumber < (num_blocks / UF2_BLOCK_SIZE); blockNumber++) {
			Msg.info(this, "reading block[" + Long.toHexString(blockNumber) + "]");
			long ptr = blockNumber * UF2_BLOCK_SIZE;
			Msg.info(this, "moving to " + Long.toUnsignedString(ptr, 16));
			populateBlock(br, ptr);
			long offset = ptr + 32; // account for the header
			String name = "block_" + Long.toUnsignedString(m_blockNo, 16);
			try {
				in.skip(offset);
				mem.createInitializedBlock(name, addressSpace.getAddress(m_targetAddr),
						in, m_payloadSize, monitor, false);
				in.skip(UF2_BLOCK_SIZE - offset - m_payloadSize);

			} catch (LockException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (MemoryConflictException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (AddressOverflowException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (AddressOutOfBoundsException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 

		    //printUF2Block();
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
	
	public void printUF2Block() {
		String output = "";
	    output += "m_magicStart0: " + Long.toUnsignedString(m_magicStart0, 16) + System.lineSeparator();
	    output += "m_magicStart1: " + Long.toUnsignedString(m_magicStart1, 16) + System.lineSeparator();
	    output += "m_flags: " + Long.toUnsignedString(m_flags, 16) + System.lineSeparator();
	    output += "m_targetAddr: " + Long.toUnsignedString(m_targetAddr, 16) + System.lineSeparator();
	    output += "m_payloadSize: " + Long.toUnsignedString(m_payloadSize, 16) + System.lineSeparator();
	    output += "m_blockNo: " + Long.toUnsignedString(m_blockNo, 16) + System.lineSeparator();
	    output += "m_numBlocks: " + Long.toUnsignedString(m_numBlocks, 16) + System.lineSeparator();
	    output += "m_fileSize: " + Long.toUnsignedString(m_fileSize, 16) + System.lineSeparator();
	    //output += "m_data: " + Long.toUnsignedString(m_data, 16) + System.lineSeparator();
	    output += "m_magicEnd: " + Long.toUnsignedString(m_magicEnd, 16) + System.lineSeparator();
	    Msg.info(this, output);
	}
	
	private void populateBlock(BinaryReader br, long idx) {
		if (br == null) {
			return;
		}
		br.setPointerIndex(idx);
		try {
			m_magicStart0 = br.readNextUnsignedInt();
		    m_magicStart1 = br.readNextUnsignedInt();
		    m_flags       = br.readNextUnsignedInt();
		    m_targetAddr  = br.readNextUnsignedInt();
		    m_payloadSize = br.readNextUnsignedInt();
		    m_blockNo     = br.readNextUnsignedInt();
		    m_numBlocks   = br.readNextUnsignedInt();
		    m_fileSize    = br.readNextUnsignedInt();
		    m_data		  = br.readNextByteArray((int) UF2_DATA_BLOCK_SIZE);
		    m_magicEnd	  = br.readNextUnsignedInt();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	    printUF2Block();
	}
	
}
