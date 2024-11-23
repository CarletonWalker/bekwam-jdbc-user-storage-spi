-- script to test a second instance of the component in the realm
CREATE TABLE us_user_3 (
                         id SERIAL PRIMARY KEY,
                         username VARCHAR(100) UNIQUE,
                         password VARCHAR(250) NOT NULL,
                         email VARCHAR(100),
                         name VARCHAR(100)
);

CREATE TABLE us_role_3 (
                         id SERIAL PRIMARY KEY,
                         name VARCHAR(100) UNIQUE
);

CREATE TABLE us_user_role_3 (
                              id SERIAL PRIMARY KEY,
                              user_id int NOT NULL REFERENCES us_user(id),
                              role_id int NOT NULL REFERENCES us_role(id)
);
