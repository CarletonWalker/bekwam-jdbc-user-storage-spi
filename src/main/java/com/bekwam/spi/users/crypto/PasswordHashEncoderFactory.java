package com.bekwam.spi.users.crypto;

/**
 * Factory for PasswordHashEncoder objects
 *
 * @since 1.1
 * @author carl
 */
public class PasswordHashEncoderFactory {

    public static PasswordHashEncoder create(
            HashFunctionType hashFunction,
            BinaryEncoderType binaryEncoder,
            String salt,
            int nIterations,
            int keyLength
    ) {

        return switch(hashFunction ) {
            case SHA_256,
                    SHA_384,
                    SHA_512,
                    SHA3_224,
                    SHA3_256,
                    SHA3_384,
                    SHA3_512 -> new SimplePasswordHashEncoder(hashFunction);
            case     PBKDF2WithHmacSHA224,
                     PBKDF2WithHmacSHA256,
                     PBKDF2WithHmacSHA384,
                     PBKDF2WithHmacSHA512 -> new SaltedPasswordHashEncoder(hashFunction, binaryEncoder, salt, nIterations, keyLength);
        };
    }
}
