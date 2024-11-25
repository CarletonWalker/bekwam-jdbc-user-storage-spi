package com.bekwam.spi.users.data;

/**
 * User entity filled in by provided SQL
 *
 * @param username
 * @param password
 * @param name
 * @param email
 *
 */
public record User(String username, String password, String name, String email, String salt) {
    // override toString so that password isn't exposed
    @Override
    public String toString() {
        return "User{" +
                "username='" + username + '\'' +
                ", name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", salt='" + salt + '\'' +
                '}';
    }
}
