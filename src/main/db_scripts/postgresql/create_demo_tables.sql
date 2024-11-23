/**********************************************************************
These tables and test data demonstrate the SPI
**********************************************************************/

-- must have pg_crypto available postgres-wide and enabled for this DB
CREATE EXTENSION pgcrypto;

CREATE TABLE bk_user (
                         id SERIAL PRIMARY KEY,
                         username VARCHAR(100) UNIQUE,
                         password VARCHAR(255) NOT NULL,
                         email VARCHAR(100),
                         name VARCHAR(100)
);

/*
  Allows for 6 SPI providers (sha256,384,512) x (base64,hex) where the user
  and SPI must match the configured hashing function and binary encoder

  Toggle enabled/disabled for the different test cases.  Since all the users
  are in the same table, this won't fall through to other providers if the
  hash is incorrect.  (It's treated as a bad password against the first
  SPI instance.)

  All hashing functions and encoding combinations go in the same table.  Only
  one of these users will be available in a SPI.  For instance, if the SPI
  is configured for SHA-256 with Base64, only user256b will be able to login with
  a successful password.
*/

INSERT INTO bk_user (username, password) VALUES ('user256b', encode(digest('abc123', 'sha256'), 'base64'));
INSERT INTO bk_user (username, password) VALUES ('user384b', encode(digest('def456', 'sha384'), 'base64'));

-- Had difficulty with a newline in the long encoded string so manually inserted the following ubuntu command

-- echo -n def456 | openssl dgst -sha512 -binary | base64 --wrap=0
INSERT INTO bk_user (username, password) VALUES ('user512b', encode(digest('def456', 'sha512'), 'base64'));

INSERT INTO bk_user (username, password) VALUES ('user256h', encode(digest('abc123', 'sha256'), 'hex'));
INSERT INTO bk_user (username, password) VALUES ('user384h', encode(digest('def456', 'sha384'), 'hex'));
INSERT INTO bk_user (username, password) VALUES ('user512h', encode(digest('def456', 'sha512'), 'hex'));

CREATE TABLE bk_role (
                         id SERIAL PRIMARY KEY,
                         name VARCHAR(100) UNIQUE
);

INSERT INTO bk_role (name) VALUES ('user');

CREATE TABLE bk_user_role (
                              id SERIAL PRIMARY KEY,
                              user_id int NOT NULL REFERENCES bk_user(id),
                              role_id int NOT NULL REFERENCES bk_role(id)
);

/*
All users have the 'user' role
*/
INSERT INTO bk_user_role (user_id, role_id)
SELECT bk_user.id, bk_role.id
FROM bk_user CROSS JOIN bk_role WHERE bk_role.name = 'user';

/*
Users Query on config screen (strip semicolon)
*/
SELECT username, password FROM bk_user WHERE username = ?;

/*
Roles Query on config screen (strip semicolon)
*/
SELECT username, bk_role.name
FROM bk_user
JOIN bk_user_role ON (bk_user_role.user_id = bk_user.id)
JOIN bk_role ON (bk_user_role.role_id = bk_role.id)
WHERE bk_user.username = ?;

/*
Select All Users Query on config screen (strip semicolon)
*/
SELECT username, password, name, email FROM bk_user ORDER BY username;

/*
Search Users Query on config screen (strip semicolon)
*/
SELECT username, password, name, email
FROM bk_user
WHERE username LIKE ? OR name LIKE ? OR email LIKE ?
ORDER BY username;
