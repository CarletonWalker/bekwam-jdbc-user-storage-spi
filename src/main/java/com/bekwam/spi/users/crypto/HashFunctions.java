package com.bekwam.spi.users.crypto;

import org.apache.commons.codec.digest.DigestUtils;
import org.jboss.logging.Logger;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Hashes cleartext
 *
 * @author carl
 * @since 1.0
 */
public class HashFunctions {

    private static final Logger LOGGER = Logger.getLogger(HashFunctions.class);

    public static byte[] sha256(String clearText) {
        if( clearText == null || clearText.isEmpty()) {
            throw new IllegalArgumentException("sha256 clearText cannot be null or empty");
        }
        return DigestUtils.sha256(clearText.getBytes());
    }
    public static byte[] sha384(String clearText) {
        if( clearText == null || clearText.isEmpty()) {
            throw new IllegalArgumentException("sha384 clearText cannot be null or empty");
        }
        return DigestUtils.sha384(clearText.getBytes());
    }
    public static byte[] sha512(String clearText) {
        if( clearText == null || clearText.isEmpty()) {
            throw new IllegalArgumentException("sha512 clearText cannot be null or empty");
        }
        return DigestUtils.sha512(clearText.getBytes());
    }
    public static byte[] sha3_224(String clearText) {
        if( clearText == null || clearText.isEmpty()) {
            throw new IllegalArgumentException("sha3_224 clearText cannot be null or empty");
        }
        return DigestUtils.sha3_224(clearText.getBytes());
    }
    public static byte[] sha3_256(String clearText) {
        if( clearText == null || clearText.isEmpty()) {
            throw new IllegalArgumentException("sha3_256 clearText cannot be null or empty");
        }
        return DigestUtils.sha3_256(clearText.getBytes());
    }
    public static byte[] sha3_384(String clearText) {
        if( clearText == null || clearText.isEmpty()) {
            throw new IllegalArgumentException("sha3_384 clearText cannot be null or empty");
        }
        return DigestUtils.sha3_384(clearText.getBytes());
    }
    public static byte[] sha3_512(String clearText) {
        if( clearText == null || clearText.isEmpty()) {
            throw new IllegalArgumentException("sha3_512 clearText cannot be null or empty");
        }
        return DigestUtils.sha3_512(clearText.getBytes());
    }

    public static byte[] pbkdf2_224(String clearText, byte[] salt, int nIterations, int keyLengthInBits) {
        return doPBKDF2("PBKDF2WithHmacSHA224", clearText, salt, nIterations, keyLengthInBits);
    }

    public static byte[] pbkdf2_256(String clearText, byte[] salt, int nIterations, int keyLengthInBits) {
        return doPBKDF2("PBKDF2WithHmacSHA256", clearText, salt, nIterations, keyLengthInBits);
    }

    public static byte[] pbkdf2_384(String clearText, byte[] salt, int nIterations, int keyLengthInBits) {
        return doPBKDF2("PBKDF2WithHmacSHA384", clearText, salt, nIterations, keyLengthInBits);
    }

    public static byte[] pbkdf2_512(String clearText, byte[] salt, int nIterations, int keyLengthInBits) {
        return doPBKDF2("PBKDF2WithHmacSHA512", clearText, salt, nIterations, keyLengthInBits);
    }

    protected static byte[] doPBKDF2(String algorithm, String clearText, byte[] salt, int nIterations, int keyLengthInBits) {
        if( clearText == null || clearText.isEmpty()) {
            throw new IllegalArgumentException(algorithm + " clearText cannot be null or empty");
        }
        if( salt == null) {
            throw new IllegalArgumentException(algorithm + " salt cannot be null");
        }
        var spec = new PBEKeySpec(clearText.toCharArray(), salt, nIterations, keyLengthInBits);
        try {
            var skf = SecretKeyFactory.getInstance(algorithm);
            return skf.generateSecret(spec).getEncoded();
        } catch(Exception exc) {
            LOGGER.error("unable to hash a password for " + algorithm, exc);
            throw new RuntimeException("unable to hash a password for " + algorithm + "; " + exc.getMessage());
        }
    }
}
