/* ###
 * IP: wyattearp
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
 *
 * @author Wyatt Neal (https://github.com/wyattearp)
 * @category Loader
 */
package uf2loader;

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
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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

  private Map<Long, String> familyMap;

  private synchronized void loadFamilyMap() {
    if (familyMap != null) {
      return;
    }
    familyMap = new HashMap<>();
    Properties props = new Properties();
    try {
      props.load(getClass().getResourceAsStream("/uf2families.properties"));
      for (String key : props.stringPropertyNames()) {
        long id = Long.parseLong(key, 16);
        String value = props.getProperty(key);
        familyMap.put(id, value.split("\\|")[0]);
      }
    } catch (Exception e) {
      Msg.error(this, "Failed to load UF2 family IDs: " + e.getMessage());
    }
  }

  @Override
  public String getName() {
    return "UF2 Loader";
  }

  @Override
  public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider)
      throws IOException {
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

    loadFamilyMap();

    if (hasFamilyId) {
      String boardName = familyMap.get(familyIdOrFileSize);
      Msg.info(this,
               "UF2 Family ID: " + Long.toHexString(familyIdOrFileSize) +
                   (boardName != null ? " (" + boardName + ")" : " (Unknown)"));
    }

    String language = "ARM:LE:32:Cortex"; // Default
    if (hasFamilyId) {
      language = getLanguageForFamily(familyIdOrFileSize);
    }

    loadSpecs.add(new LoadSpec(
        this, 0, new LanguageCompilerSpecPair(language, "default"), true));

    return loadSpecs;
  }

  private String getLanguageForFamily(long familyId) {
    // ESP32 variants
    if (familyId == 0x1c5f21b0L || familyId == 0xbfdd4eeeL ||
        familyId == 0xc47e5767L) {
      return "Xtensa:LE:32:default";
    }
    // ESP32-C3 (RISC-V)
    if (familyId == 0xd42ba06cL) {
      return "RISCV:LE:32:RV32I";
    }
    // ESP8266
    if (familyId == 0x7eab61edL) {
      return "Xtensa:LE:32:default";
    }
    // AVR
    if (familyId == 0x16573617L) {
      return "avr8:le:16:default";
    }
    return "ARM:LE:32:Cortex";
  }

  private Map<Integer, byte[]> parseExtensionTags(BinaryReader br, long offset,
                                                  long flags, long payloadSize)
      throws IOException {
    Map<Integer, byte[]> tags = new HashMap<>();
    if ((flags & 0x00008000L) == 0) {
      return tags;
    }

    long pos = offset + 32 + payloadSize;
    long end = offset + UF2_BLOCK_SIZE - 4;

    while (pos + 4 <= end) {
      int size = br.readByte(pos) & 0xFF;
      if (size == 0)
        break;

      int type = br.readInt(pos + 1) & 0xFFFFFF;
      if (pos + size > end)
        break;

      tags.put(type, br.readByteArray(pos + 4, size - 4));
      pos += (size + 3) & ~3; // 4-byte alignment
    }

    return tags;
  }

  private boolean isValidBlock(BinaryReader br, long offset)
      throws IOException {
    return br.readUnsignedInt(offset) == UF2_FIRST_MAGIC &&
        br.readUnsignedInt(offset + 4) == UF2_SECOND_MAGIC &&
        br.readUnsignedInt(offset + UF2_BLOCK_SIZE - 4) == UF2_FINAL_MAGIC;
  }

  @Override
  protected void load(Program program, Loader.ImporterSettings settings)
      throws CancelledException, IOException {
    ByteProvider provider = settings.provider();
    TaskMonitor monitor = settings.monitor();
    MessageLog log = settings.log();

    BinaryReader br = new BinaryReader(provider, true);
    Memory mem = program.getMemory();
    FileBytes fileBytes =
        MemoryBlockUtils.createFileBytes(program, provider, monitor);

    long numBlocks = provider.length() / UF2_BLOCK_SIZE;
    monitor.setMessage("Loading UF2 blocks...");
    monitor.initialize(numBlocks);

    MemoryBlock lastBlock = null;
    Map<Integer, byte[]> allTags = new HashMap<>();
    Long minAddr = null;

    for (long i = 0; i < numBlocks; i++) {
      monitor.checkCancelled();
      long offset = i * UF2_BLOCK_SIZE;

      if (!isValidBlock(br, offset)) {
        continue;
      }

      long flags = br.readUnsignedInt(offset + 8);
      long targetAddr = br.readUnsignedInt(offset + 12);
      long payloadSize = br.readUnsignedInt(offset + 16);

      if ((flags & 0x00001000L) != 0) {
        log.appendMsg(
            "File Container Mode detected. This loader currently treats payloads as raw memory.");
      }

      // Collect tags from all blocks (merging)
      allTags.putAll(parseExtensionTags(br, offset, flags, payloadSize));

      Address addr =
          program.getAddressFactory().getDefaultAddressSpace().getAddress(
              targetAddr);
      if (minAddr == null || targetAddr < minAddr) {
        minAddr = targetAddr;
      }

      MemoryBlock currentBlock =
          createBlock(mem, fileBytes, offset + 32, addr, payloadSize, log);
      if (currentBlock == null) {
        continue;
      }

      lastBlock = tryMerge(mem, lastBlock, currentBlock, log);
      monitor.setProgress(i + 1);
    }

    processMetadata(program, allTags, minAddr, log);
    Msg.info(this, "UF2 load complete. Blocks merged into " +
                       mem.getBlocks().length + " segment(s).");
  }

  private void processMetadata(Program program, Map<Integer, byte[]> tags,
                               Long minAddr, MessageLog log) {
    // Firmware Version: 0x9fc7bc
    if (tags.containsKey(0x9fc7bc)) {
      String version = new String(tags.get(0x9fc7bc)).trim();
      log.appendMsg("Firmware Version: " + version);
      program.getOptions(Program.PROGRAM_INFO)
          .setString("Firmware Version", version);
    }

    // Device Description: 0x650d9d
    if (tags.containsKey(0x650d9d)) {
      String desc = new String(tags.get(0x650d9d)).trim();
      log.appendMsg("Device Description: " + desc);
      program.getOptions(Program.PROGRAM_INFO)
          .setString("Device Description", desc);
    }

    // Heuristic Entry Point
    if (minAddr != null) {
      setEntryPoint(program, minAddr, log);
    }
  }

  private void setEntryPoint(Program program, long minAddr, MessageLog log) {
    try {
      Address baseAddr =
          program.getAddressFactory().getDefaultAddressSpace().getAddress(
              minAddr);
      Address entryAddr = baseAddr;

      // ARM Heuristic: Entry is at [Base + 4]
      if (program.getLanguage().getProcessor().toString().equalsIgnoreCase(
              "ARM")) {
        int resetVector = program.getMemory().getInt(baseAddr.add(4));
        // Basic sanity check: reset vector should be within some memory block
        entryAddr =
            program.getAddressFactory().getDefaultAddressSpace().getAddress(
                resetVector & ~1);
        if (!program.getMemory().contains(entryAddr)) {
          entryAddr = baseAddr; // Fallback
        }
      }

      program.getSymbolTable().addExternalEntryPoint(entryAddr);
      log.appendMsg("Heuristic entry point set to: " + entryAddr);
    } catch (Exception e) {
      log.appendMsg("Failed to set heuristic entry point: " + e.getMessage());
    }
  }

  private MemoryBlock createBlock(Memory mem, FileBytes fileBytes,
                                  long fileOffset, Address addr, long size,
                                  MessageLog log) {
    try {
      String name = "uf2_" + addr;
      MemoryBlock block = mem.createInitializedBlock(name, addr, fileBytes,
                                                     fileOffset, size, false);
      block.setRead(true);
      block.setWrite(true);
      block.setExecute(true);
      return block;
    } catch (Exception e) {
      log.appendMsg("Failed to create block at " + addr + ": " +
                    e.getMessage());
      return null;
    }
  }

  private MemoryBlock tryMerge(Memory mem, MemoryBlock last,
                               MemoryBlock current, MessageLog log) {
    if (last == null) {
      return current;
    }

    if (!last.getEnd().add(1).equals(current.getStart())) {
      return current;
    }

    try {
      return mem.join(last, current);
    } catch (Exception e) {
      log.appendMsg("Failed to merge blocks: " + last.getName() + " and " +
                    current.getName() + ". " + e.getMessage());
      return current;
    }
  }

  @Override
  public List<Option>
  getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
                    DomainObject domainObject, boolean isLoadIntoProgram,
                    boolean isLoadOnlyLibraries) {
    return super.getDefaultOptions(provider, loadSpec, domainObject,
                                   isLoadIntoProgram, isLoadOnlyLibraries);
  }
}
