package com.bekwam.spi.users.crypto;

import org.jboss.logging.Logger;

/**
 * SHA384 implementation of encoded passwords
 *
 * @author carl
 * @since 1.0
 */
public class SHA384PasswordEncoder implements PasswordEncoder {
    private static final Logger LOGGER = Logger.getLogger(SHA384PasswordEncoder.class);
    @Override
    public String encodeBase64(String password) {
        if( password == null || password.isEmpty() ) {
            LOGGER.warn("password is null or empty");
            return null;
        }
        return BinaryEncoders.base64(HashFunctions.sha384(password));
    }
    @Override
    public String encodeHex(String password) {
        if( password == null || password.isEmpty() ) {
            LOGGER.warn("password is null or empty");
            return null;
        }
        return BinaryEncoders.hex(HashFunctions.sha384(password));
    }
}
