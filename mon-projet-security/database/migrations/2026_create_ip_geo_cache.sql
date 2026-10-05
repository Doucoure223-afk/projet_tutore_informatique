-- =============================================================================
-- Migration : Cache de géolocalisation IP (pour service IpGeolocation)
-- =============================================================================

USE `mon_projet_securite`;

CREATE TABLE IF NOT EXISTS `ip_geo_cache` (
  `ip_address` varchar(45) NOT NULL,
  `country_code` char(2) NOT NULL DEFAULT 'XX',
  `country_name` varchar(100) NOT NULL DEFAULT '',
  `region` varchar(100) DEFAULT NULL,
  `city` varchar(100) DEFAULT NULL,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
