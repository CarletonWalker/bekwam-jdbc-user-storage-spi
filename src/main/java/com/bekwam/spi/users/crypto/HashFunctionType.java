package com.bekwam.spi.users.crypto;

/**
 * Supported hash functions
 *
 * @since 1.1
 * @author carl
 */
public enum HashFunctionType {
    SHA_256,
    SHA_384,
    SHA_512,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    PBKDF2WithHmacSHA224,
    PBKDF2WithHmacSHA256,
    PBKDF2WithHmacSHA384,
    PBKDF2WithHmacSHA512
}
