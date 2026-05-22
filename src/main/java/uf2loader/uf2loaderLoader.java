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
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
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
	public static final long UF2_SECOND_MAGIC = 0x9E5D5157L;
	public static final long UF2_FINAL_MAGIC = 0x0AB16F30;
	public static final long UF2_DATA_BLOCK_SIZE = 476;

	private static final Map<Long, String> FAMILY_LOOKUP = Stream.of(new Object[][] {
			{ 0x16573617L, "Microchip (Atmel) ATmega32" },
			{ 0x1851780aL, "Microchip (Atmel) SAML21" },
			{ 0x1b57745fL, "Nordic NRF52" },
			{ 0x1c5f21b0L, "ESP32" },
			{ 0x1e1f432dL, "ST STM32L1xx" },
			{ 0x202e3a91L, "ST STM32L0xx" },
			{ 0x21460ff0L, "ST STM32WLxx" },
			{ 0x2abc77ecL, "NXP LPC55xx" },
			{ 0x300f5633L, "ST STM32G0xx" },
			{ 0x31d228c6L, "GD32F350" },
			{ 0x04240bdfL, "ST STM32L5xx" },
			{ 0x4c71240aL, "ST STM32G4xx" },
			{ 0x4fb2d5bdL, "NXP i.MX RT10XX" },
			{ 0x53b80f00L, "ST STM32F7xx" },
			{ 0x55114460L, "Microchip (Atmel) SAMD51" },
			{ 0x57755a57L, "ST STM32F401" },
			{ 0x5a18069bL, "Cypress FX2" },
			{ 0x5d1a0a2eL, "ST STM32F2xx" },
			{ 0x5ee21072L, "ST STM32F103" },
			{ 0x647824b6L, "ST STM32F0xx" },
			{ 0x68ed2b88L, "Microchip (Atmel) SAMD21" },
			{ 0x6b846188L, "ST STM32F3xx" },
			{ 0x6d0922faL, "ST STM32F407" },
			{ 0x6db66082L, "ST STM32H7xx" },
			{ 0x70d16653L, "ST STM32WBxx" },
			{ 0x7eab61edL, "ESP8266" },
			{ 0x7f83e793L, "NXP KL32L2x" },
			{ 0x8fb060feL, "ST STM32F407VG" },
			{ 0xada52840L, "Nordic NRF52840" },
			{ 0xbfdd4eeeL, "ESP32-S2" },
			{ 0xc47e5767L, "ESP32-S3" },
			{ 0xd42ba06cL, "ESP32-C3" },
			{ 0xe48bff56L, "Raspberry Pi RP2040" },
			{ 0x00ff6919L, "ST STM32L4xx" }
	}).collect(Collectors.toMap(data -> (Long) data[0], data -> (String) data[1]));

	@Override
	public String getName() {
		return "UF2 Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < UF2_BLOCK_SIZE) {
			return loadSpecs;
		}

		BinaryReader br = new BinaryReader(provider, true);
		if (!isValidBlock(br, 0)) {
			return loadSpecs;
		}

		long flags = br.readUnsignedInt(8);
		long familyIdOrFileSize = br.readUnsignedInt(28);
		boolean hasFamilyId = (flags & 0x00002000L) != 0;
		
		if (hasFamilyId) {
			String boardName = FAMILY_LOOKUP.get(familyIdOrFileSize);
			Msg.info(this, "UF2 Family ID: " + Long.toHexString(familyIdOrFileSize) + 
				(boardName != null ? " (" + boardName + ")" : " (Unknown)"));
		}

		String language = "ARM:LE:32:Cortex"; // Default
		if (hasFamilyId) {
			if (familyIdOrFileSize == 0x1c5f21b0L || familyIdOrFileSize == 0xbfdd4eeeL || familyIdOrFileSize == 0xc47e5767L) {
				language = "Xtensa:LE:32:default";
			} else if (familyIdOrFileSize == 0xd42ba06cL) {
				language = "RISCV:LE:32:RV32I";
			} else if (familyIdOrFileSize == 0x7eab61edL) {
				language = "Xtensa:LE:32:default"; // ESP8266
			} else if (familyIdOrFileSize == 0x16573617L) {
				language = "avr8:le:16:default";
			}
		}

		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(language, "default"), true));

		return loadSpecs;
	}

	private boolean isValidBlock(BinaryReader br, long offset) throws IOException {
		return br.readUnsignedInt(offset) == UF2_FIRST_MAGIC &&
				br.readUnsignedInt(offset + 4) == UF2_SECOND_MAGIC &&
				br.readUnsignedInt(offset + UF2_BLOCK_SIZE - 4) == UF2_FINAL_MAGIC;
	}

	@Override
	protected void load(Program program, Loader.ImporterSettings settings) throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		TaskMonitor monitor = settings.monitor();
		MessageLog log = settings.log();

		BinaryReader br = new BinaryReader(provider, true);
		Memory mem = program.getMemory();
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

		long numBlocks = provider.length() / UF2_BLOCK_SIZE;
		monitor.setMessage("Loading UF2 blocks...");
		monitor.initialize(numBlocks);

		MemoryBlock lastBlock = null;

		for (long i = 0; i < numBlocks; i++) {
			monitor.checkCancelled();
			long offset = i * UF2_BLOCK_SIZE;

			if (!isValidBlock(br, offset)) {
				continue;
			}

			long targetAddr = br.readUnsignedInt(offset + 12);
			long payloadSize = br.readUnsignedInt(offset + 16);
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(targetAddr);

			MemoryBlock currentBlock = createBlock(mem, fileBytes, offset + 32, addr, payloadSize, log);
			if (currentBlock == null) {
				continue;
			}

			lastBlock = tryMerge(mem, lastBlock, currentBlock, log);
			monitor.setProgress(i + 1);
		}
		
		Msg.info(this, "UF2 load complete. Blocks merged into " + mem.getBlocks().length + " segment(s).");
	}

	private MemoryBlock createBlock(Memory mem, FileBytes fileBytes, long fileOffset, Address addr, long size, MessageLog log) {
		try {
			String name = "uf2_" + addr;
			MemoryBlock block = mem.createInitializedBlock(name, addr, fileBytes, fileOffset, size, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(true);
			return block;
		} catch (Exception e) {
			log.appendMsg("Failed to create block at " + addr + ": " + e.getMessage());
			return null;
		}
	}

	private MemoryBlock tryMerge(Memory mem, MemoryBlock last, MemoryBlock current, MessageLog log) {
		if (last == null) {
			return current;
		}

		if (!last.getEnd().add(1).equals(current.getStart())) {
			return current;
		}

		try {
			return mem.join(last, current);
		} catch (Exception e) {
			log.appendMsg("Failed to merge blocks: " + last.getName() + " and " + current.getName() + ". " + e.getMessage());
			return current;
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram, boolean isLoadOnlyLibraries) {
		return super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram, isLoadOnlyLibraries);
	}
}
