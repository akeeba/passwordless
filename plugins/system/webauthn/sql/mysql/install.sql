CREATE TABLE IF NOT EXISTS `#__webauthn_credentials`
(
  `id`         VARCHAR(1000)   NOT NULL COMMENT 'Credential ID',
  `user_id`    BIGINT UNSIGNED NOT NULL COMMENT 'Joomla User ID',
  `label`      VARCHAR(190)    NOT NULL COMMENT 'Human readable label',
  `credential` MEDIUMTEXT      NOT NULL COMMENT 'Attested credential data, JSON format',
  `counter`    BIGINT          NOT NULL DEFAULT 0 COMMENT 'Last seen counter',
  PRIMARY KEY (`id`(100)),
  INDEX (`user_id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  DEFAULT COLLATE = utf8mb4_unicode_ci;