package com.bekwam.spi.users.crypto;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64;

import java.io.IOException;

/**
 * Implementation of PBKDF2 salted password functions
 *
 * @since 1.1
 * @author carl
 */
public class SaltedPasswordHashEncoder implements PasswordHashEncoder {

    private static final Logger LOGGER = Logger.getLogger(SaltedPasswordHashEncoder.class);

    private final HashFunctionType hashFunction;
    private final String salt;
    private final int nIterations;
    private final int keyLength;
    private final BinaryEncoderType binaryEncoder;

    public SaltedPasswordHashEncoder(
            HashFunctionType hashFunction,
            BinaryEncoderType binaryEncoder,
            String salt,
            int nIterations,
            int keyLength
    ) {
        this.hashFunction = hashFunction;
        this.binaryEncoder = binaryEncoder;
        this.salt = salt;
        this.nIterations = nIterations;
        this.keyLength = keyLength;
    }

    @Override
    public String encodeBase64(String password) {
        LOGGER.trace("encodeBase64");
        if( password == null || password.isEmpty() ) {
            LOGGER.warn("password is null or empty");
            return null;
        }
        try {
            return BinaryEncoders.base64(hash(hashFunction, binaryEncoder, password, salt, nIterations, keyLength));
        } catch(DecoderException | IOException exc) {
            throw new RuntimeException("unable to decode salt=" + salt + " with binaryEncoder=" + binaryEncoder.name());
        }
    }

    @Override
    public String encodeHex(String password) {
        LOGGER.trace("encodeBase64");
        if( password == null || password.isEmpty() ) {
            LOGGER.warn("password is null or empty");
            return null;
        }
        try {
            return BinaryEncoders.hex(hash(hashFunction, binaryEncoder, password, salt, nIterations, keyLength));
        } catch(DecoderException | IOException exc) {
            throw new RuntimeException("unable to decode salt=" + salt + " with binaryEncoder=" + binaryEncoder.name());
        }
    }

    protected static byte[] hash(
            HashFunctionType hashFunction,
            BinaryEncoderType binaryEncoder,
            String input,
            String salt,
            int nIterations,
            int keyLength
    ) throws DecoderException, IOException {
        LOGGER.trace("hash function=" + hashFunction.name());
        var salt_b = switch(binaryEncoder) {
            case HEX -> Hex.decodeHex(salt);
            case BASE64 -> Base64.decode(salt);
        };
        return switch(hashFunction) {
            case PBKDF2WithHmacSHA224 -> HashFunctions.pbkdf2_224(input, salt_b, nIterations, keyLength);
            case PBKDF2WithHmacSHA256 -> HashFunctions.pbkdf2_256(input, salt_b, nIterations, keyLength);
            case PBKDF2WithHmacSHA384 -> HashFunctions.pbkdf2_384(input, salt_b, nIterations, keyLength);
            case PBKDF2WithHmacSHA512 -> HashFunctions.pbkdf2_512(input, salt_b, nIterations, keyLength);
            default -> throw new UnsupportedOperationException(hashFunction.name());
        };
    }
}
