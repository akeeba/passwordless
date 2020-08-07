/*
 * @package   AkeebaPasswordlessLogin
 * @copyright Copyright (c)2018-2020 Nicholas K. Dionysopoulos / Akeeba Ltd
 * @license   GNU General Public License version 3, or later
 */

CREATE TABLE IF NOT EXISTS `#__passwordless_credentials`
(
  `id`         VARCHAR(1000)   NOT NULL COMMENT 'Credential ID',
  `user_id`    VARCHAR(128)    NOT NULL COMMENT 'User handle',
  `label`      VARCHAR(190)    NOT NULL COMMENT 'Human readable label',
  `credential` MEDIUMTEXT      NOT NULL COMMENT 'Attested credential data, JSON format',
  PRIMARY KEY (`id`(100)),
  INDEX (`user_id`(100))
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  DEFAULT COLLATE = utf8mb4_unicode_ci;