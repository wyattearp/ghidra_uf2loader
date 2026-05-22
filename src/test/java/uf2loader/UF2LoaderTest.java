package uf2loader;

import static org.junit.Assert.*;
import org.junit.Test;
import java.io.IOException;
import java.util.Map;

public class UF2LoaderTest {

    @Test
    public void testFamilyMapLoading() throws IOException {
        uf2loaderLoader loader = new uf2loaderLoader();
        // This will fail initially as we haven't implemented resource loading yet
        Map<Long, String> map = loader.getFamilyMap(); 
        assertNotNull("Family map should not be null", map);
        assertTrue("Family map should contain RP2040", map.containsValue("RP2040"));
    }

    @Test
    public void testExtensionTagParsing() {
        // Mock a block with extension tags
        byte[] block = new byte[512];
        // Flag 0x8000 (has tags)
        block[8] = 0x00; block[9] = 0x80; block[10] = 0x00; block[11] = 0x00; 
        // Payload size 444
        block[16] = (byte)0xbc; block[17] = 0x01; 
        
        // Tag 1: Size 8, Type 0x9fc7bc (Firmware Version), Value "v1.2.3" (plus null)
        int tagOffset = 32 + 444;
        block[tagOffset] = 9; // Size: 1(len) + 3(type) + 5(data) = 9
        block[tagOffset+1] = (byte)0xbc; block[tagOffset+2] = (byte)0xc7; block[tagOffset+3] = (byte)0x9f;
        System.arraycopy("v1.2.3".getBytes(), 0, block, tagOffset+4, 5);
        
        // Terminator tag
        block[tagOffset+9] = 0; block[tagOffset+10] = 0; block[tagOffset+11] = 0; block[tagOffset+12] = 0;

        uf2loaderLoader loader = new uf2loaderLoader();
        Map<Integer, byte[]> tags = loader.parseExtensionTags(block);
        
        assertNotNull(tags);
        assertTrue(tags.containsKey(0x9fc7bc));
        assertEquals("v1.2.3", new String(tags.get(0x9fc7bc)).trim());
    }
}
