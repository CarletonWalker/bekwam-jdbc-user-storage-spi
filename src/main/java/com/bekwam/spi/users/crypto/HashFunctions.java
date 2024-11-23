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
}
