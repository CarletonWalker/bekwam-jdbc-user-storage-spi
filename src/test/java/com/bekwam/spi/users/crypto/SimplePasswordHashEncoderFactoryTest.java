package com.bekwam.spi.users.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Unit test for SHA256PasswordEncoderTest
 *
 * @since 1.0
 * @author carl
 */
public class SimplePasswordHashEncoderFactoryTest {

    @Test
    public void ok() {
        //
        // cross-check in linux with
        // $ echo -n 'abc123' | openssl dgst -sha256 -binary | base64
        //
/*
        assertEquals(
                "bKE9UspwyIPg8LsQHkJaiehiTeUdstI5JZOvaoQRgJA=",
                new SimplePasswordHashEncoder().encodeBase64("abc123")
        );
*/
    }

    @Test
    public void bad() {
/*
        assertNull(
                new SimplePasswordHashEncoder().encodeBase64(null)
        );
        assertNull(
                new SimplePasswordHashEncoder().encodeBase64("")
        );
*/
    }
}
