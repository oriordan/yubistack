CREATE TABLE user_yubikeys (
  user_id INT NOT NULL,
  yubikey_id INT NOT NULL
);

CREATE TABLE users (
  id INT NOT NULL UNIQUE,
  name VARCHAR(32) NOT NULL,
  auth VARCHAR(128) DEFAULT NULL,
  attribute_association_id INT DEFAULT NULL,
  PRIMARY KEY (id)
);

CREATE TABLE yubikeys (
  id INT NOT NULL UNIQUE,
  prefix VARCHAR(32) NOT NULL,
  enabled BOOLEAN DEFAULT TRUE,
  attribute_association_id INT DEFAULT NULL,
  PRIMARY KEY (id)
);
