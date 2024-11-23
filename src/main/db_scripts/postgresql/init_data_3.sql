-- script to test a second instance of the component in the realm

INSERT INTO us_user_3 (username, password) VALUES ('theuser', encode(digest('ghi789', 'sha384'), 'hex'));

INSERT INTO us_role_3 (name) VALUES ('user');

INSERT INTO us_user_role_3 (user_id, role_id)
SELECT us_user_3.id, us_role_3.id
FROM us_user_3 CROSS JOIN us_role_3 WHERE username = 'theuser' AND us_role_3.name = 'user'

-- query to verify joins
SELECT username, password, us_role_3.name
FROM us_user_3
         JOIN us_user_role_3 ON (us_user_role_3.user_id = us_user_3.id)
         JOIN us_role_3 ON (us_user_role_3.role_id = us_role_3.id)


UPDATE us_user_3 SET PASSWORD = encode(digest('ghi789', 'sha512'), 'hex') WHERE username = 'theuser'
