package com.bekwam.spi.users.crypto;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

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
    }
}
