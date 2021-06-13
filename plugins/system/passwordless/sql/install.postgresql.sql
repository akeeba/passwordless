/*
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2021 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

CREATE TABLE IF NOT EXISTS "#__passwordless_credentials"
(
    "id"         varchar(1000)    NOT NULL,
    "user_id"    varchar(128)   NOT NULL,
    "label"      varchar(190)     NOT NULL,
    "credential" TEXT             NOT NULL,
    PRIMARY KEY ("id")
);
