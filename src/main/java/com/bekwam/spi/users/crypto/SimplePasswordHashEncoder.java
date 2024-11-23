package com.bekwam.spi.users.crypto;

import org.jboss.logging.Logger;

/**
 * SHA256 implementation of encoded passwords
 *
 * @author carl
 * @since 1.0
 */
public class SimplePasswordHashEncoder implements PasswordHashEncoder {
    private static final Logger LOGGER = Logger.getLogger(SimplePasswordHashEncoder.class);

    private final HashFunctionType hashFunction;

    public SimplePasswordHashEncoder(HashFunctionType hashFunction) {
        if( hashFunction == null ) {
            throw new IllegalArgumentException("hashFunction cannot be null");
        }
        this.hashFunction = hashFunction;
    }

    @Override
    public String encodeBase64(String password) {
        LOGGER.trace("encodeBase64");
        if( password == null || password.isEmpty() ) {
            LOGGER.warn("password is null or empty");
            return null;
        }
        return BinaryEncoders.base64(hash(hashFunction, password));
    }
    @Override
    public String encodeHex(String password) {
        LOGGER.trace("encodeHex");
        if( password == null || password.isEmpty() ) {
            LOGGER.warn("password is null or empty");
            return null;
        }
        return BinaryEncoders.hex(hash(hashFunction, password));
    }

    protected static byte[] hash(HashFunctionType hashFunction, String input) {
        LOGGER.trace("hash function=" + hashFunction.name());
        return switch(hashFunction) {
            case SHA_256 -> HashFunctions.sha256(input);
            case SHA_384 -> HashFunctions.sha384(input);
            case SHA_512 -> HashFunctions.sha512(input);
            case SHA3_224 -> HashFunctions.sha3_224(input);
            case SHA3_256 -> HashFunctions.sha3_256(input);
            case SHA3_384 -> HashFunctions.sha3_384(input);
            case SHA3_512 -> HashFunctions.sha3_512(input);
        };
    }
}
