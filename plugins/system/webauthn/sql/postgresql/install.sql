CREATE TABLE IF NOT EXISTS "#__webauthn_credentials"
(
  "id"         varchar(1000)    NOT NULL,
  "user_id"    BIGINT DEFAULT 0 NOT NULL,
  "credential" TEXT             NOT NULL,
  "counter"    BIGINT DEFAULT 0 NOT NULL,
  PRIMARY KEY ("id")
);

CREATE INDEX "#__webauthn_credentials_user_id" ON "#__webauthn_credentials" ("user_id");