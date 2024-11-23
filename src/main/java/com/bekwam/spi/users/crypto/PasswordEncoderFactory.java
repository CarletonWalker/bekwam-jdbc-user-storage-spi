package com.bekwam.spi.users.crypto;

/**
 * Creates PasswordEncoder objects
 *
 * @since 1.1
 * @author carl
 */
public class PasswordEncoderFactory {
    public static PasswordEncoder create(HashFunctionType hashingFunction) {
        return switch(hashingFunction) {
            case SHA_256 -> new SHA256PasswordEncoder();
            case SHA_384 -> new SHA384PasswordEncoder();
            case SHA_512 -> new SHA512PasswordEncoder();
        };
    }
}
