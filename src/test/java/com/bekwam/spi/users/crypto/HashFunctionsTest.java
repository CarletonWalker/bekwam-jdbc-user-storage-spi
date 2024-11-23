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
    }

    @Test
    public void bad() {
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha256(null));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha256(""));

        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha384(null));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha384(""));

        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha512(null));
        assertThrows(IllegalArgumentException.class, () -> HashFunctions.sha512(""));
    }
}
