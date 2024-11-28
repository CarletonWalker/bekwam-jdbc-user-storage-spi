package com.bekwam.spi.users.crypto;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test for Hash class
 *
 * @since 1.1
 * @author carl
 */
public class HashFunctionsTest {

    @Test
    public void ok() throws DecoderException {

        // echo -n abc123 | openssl dgst -sha256 -hex
        assertArrayEquals(
                Hex.decodeHex("6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090"),
                HashFunctions.sha256("abc123")
        );

        // echo -n abc123 | openssl dgst -sha384 -hex
        assertArrayEquals(
                Hex.decodeHex("a31d79891919cad24f3264479d76884f581bee32e86778373db3a124de975dd86a40fc7f399b331133b281ab4b11a6ca"),
                HashFunctions.sha384("abc123")
        );

        // echo -n abc123 | openssl dgst -sha512 -hex
        assertArrayEquals(
                Hex.decodeHex("c70b5dd9ebfb6f51d09d4132b7170c9d20750a7852f00680f65658f0310e810056e6763c34c9a00b0e940076f54495c169fc2302cceb312039271c43469507dc"),
                HashFunctions.sha512("abc123")
        );

        // echo -n abc123 | openssl dgst -sha3-224 -hex
        assertArrayEquals(
                Hex.decodeHex("026727ec105a060b02a0086a2181748f6b9ac3cea3fc347ca8675984"),
                HashFunctions.sha3_224("abc123")
        );

        // echo -n abc123 | openssl dgst -sha3-256 -hex
        assertArrayEquals(
                Hex.decodeHex("f58fa3df820114f56e1544354379820cff464c9c41cb3ca0ad0b0843c9bb67ee"),
                HashFunctions.sha3_256("abc123")
        );

        // echo -n abc123 | openssl dgst -sha3-384 -hex
        assertArrayEquals(
                Hex.decodeHex("e07300227b15a724fdf6555569e38282022d106d778aa2268898dc21639b24e1e00fcc0a6d96ffc8b3a97c7fa7296305"),
                HashFunctions.sha3_384("abc123")
        );

        // echo -n abc123 | openssl dgst -sha512 -hex
        assertArrayEquals(
                Hex.decodeHex("3274f8455be84b8c7d79f9bd93e6c8520d13f6bd2855f3bb9c006ca9f3cce25d4b924d0370f8af4e27a350fd2baeef58bc37e0f4e4a403fe64c98017fa012757"),
                HashFunctions.sha3_512("abc123")
        );

        // openssl kdf -keylen 32 -kdfopt digest:SHA224 -kdfopt salt:salt -kdfopt iter:2 -kdfopt pass:abc123 PBKDF2
        var b = HashFunctions.pbkdf2_224("abc123", "salt".getBytes(), 2, 32*8);
        var s = HexFormat.ofDelimiter(":").withUpperCase().formatHex(b);
        assertEquals("7C:82:D8:84:C6:6C:ED:13:B8:40:5B:2D:4F:46:8A:9B:30:96:22:1C:4C:C6:AE:7C:AE:9B:C6:77:63:12:8B:77", s);

        // openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt salt:salt -kdfopt iter:2 -kdfopt pass:abc123 PBKDF2
        b = HashFunctions.pbkdf2_256("abc123", "salt".getBytes(), 2, 32*8);
        s = HexFormat.ofDelimiter(":").withUpperCase().formatHex(b);
        assertEquals("5F:FE:57:1F:5F:BD:B8:85:A8:07:50:BE:3C:BD:22:C4:C8:84:50:BE:D8:72:44:29:1D:00:6B:2A:0E:8E:A1:67", s);

        // openssl kdf -keylen 32 -kdfopt digest:SHA384 -kdfopt salt:salt -kdfopt iter:2 -kdfopt pass:abc123 PBKDF2
        b = HashFunctions.pbkdf2_384("abc123", "salt".getBytes(), 2, 32*8);
        s = HexFormat.ofDelimiter(":").withUpperCase().formatHex(b);
        assertEquals("4D:14:ED:3D:FC:65:B6:E5:4E:32:6C:44:D9:52:DD:96:05:1B:F1:77:52:3A:A6:AA:B6:90:DA:C0:6E:AC:8B:35", s);

        // openssl kdf -keylen 32 -kdfopt digest:SHA512 -kdfopt salt:salt -kdfopt iter:2 -kdfopt pass:abc123 PBKDF2
        b = HashFunctions.pbkdf2_512("abc123", "salt".getBytes(), 2, 32*8);
        s = HexFormat.ofDelimiter(":").withUpperCase().formatHex(b);
        assertEquals("EB:48:24:A3:0E:C5:74:CE:48:BA:D5:3B:2E:BF:F8:2B:2E:FC:10:5A:F3:00:2F:94:20:5B:10:52:47:F2:60:BF", s);
    }

    @Test
    public void bad() {
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha256(null));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha256(""));

        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha384(null));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha384(""));

        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha512(null));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha512(""));

        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha3_224(null));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha3_224(""));

        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha3_256(null));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha3_256(""));

        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha3_384(null));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha3_384(""));

        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha3_512(null));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha3_512(""));

        assertThrows(IllegalArgumentException.class, () -> HashFunctions.pbkdf2_224(null, null, 0, 0));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.pbkdf2_224("", null, 0, 0));

        assertThrows(IllegalArgumentException.class, () -> HashFunctions.pbkdf2_256(null, null, 0, 0));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.pbkdf2_256("", null, 0, 0));

        assertThrows(IllegalArgumentException.class, () -> HashFunctions.pbkdf2_384(null, null, 0, 0));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.pbkdf2_384("", null, 0, 0));

        assertThrows(IllegalArgumentException.class, () -> HashFunctions.pbkdf2_512(null, null, 0, 0));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.pbkdf2_512("", null, 0, 0));
    }
}
