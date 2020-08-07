CREATE TABLE IF NOT EXISTS "#__passwordless_credentials"
(
  "id"         varchar(1000)    NOT NULL,
  "user_id"    varchar(12890)   NOT NULL,
  "label"      varchar(190)     NOT NULL,
  "credential" TEXT             NOT NULL,
  PRIMARY KEY ("id")
);

CREATE INDEX "#__passwordless_credentials_id" ON "#__passwordless_credentials" ("id");
CREATE INDEX "#__passwordless_credentials_user_id" ON "#__passwordless_credentials" ("user_id");