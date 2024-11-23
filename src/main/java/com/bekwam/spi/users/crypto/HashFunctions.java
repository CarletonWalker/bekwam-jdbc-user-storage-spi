package com.bekwam.spi.users.crypto;

import org.apache.commons.codec.digest.DigestUtils;

import java.util.Base64;

/**
 * Hashes cleartext
 *
 * @author carl
 * @since 1.0
 */
public class HashFunctions {
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
}
