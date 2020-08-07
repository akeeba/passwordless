/*
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2020 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

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