-- =============================================================================
-- Migration : Liste noire / liste blanche d'IP
-- =============================================================================

USE `mon_projet_securite`;

CREATE TABLE IF NOT EXISTS `ip_access_rules` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL,
  `rule_type` enum('blacklist','whitelist') NOT NULL,
  `comment` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ip_access_rules_ip` (`ip_address`),
  KEY `idx_ip_access_rules_type` (`rule_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
