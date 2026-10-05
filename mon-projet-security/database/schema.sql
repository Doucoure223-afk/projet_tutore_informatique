-- =============================================================================
-- Base de données : mon_projet_securite
-- Projet : Système de sécurité SQL Injection avec IA - Standard 2026
-- SGBD : MySQL / MariaDB (Wamp Server)
-- =============================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- -----------------------------------------------------------------------------
-- Base
-- -----------------------------------------------------------------------------
CREATE DATABASE IF NOT EXISTS `mon_projet_securite`
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE `mon_projet_securite`;

-- -----------------------------------------------------------------------------
-- Table : users
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` varchar(30) NOT NULL DEFAULT 'user',
  `login_attempts` int unsigned NOT NULL DEFAULT 0,
  `locked_until` datetime DEFAULT NULL,
  `mfa_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `last_login_at` datetime DEFAULT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `verification_token` varchar(64) DEFAULT NULL,
  `email_verified_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_users_username` (`username`),
  UNIQUE KEY `uk_users_email` (`email`),
  KEY `idx_users_deleted_at` (`deleted_at`),
  KEY `idx_users_locked_until` (`locked_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- Table : user_profiles (utilisée par inscription.php)
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS `user_profiles`;
CREATE TABLE `user_profiles` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int unsigned NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_profiles_user_id` (`user_id`),
  CONSTRAINT `fk_user_profiles_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- Table : security_incidents (alignée avec SecurityResponseFactory et structure réelle)
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS `security_incidents`;
CREATE TABLE `security_incidents` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `uuid` char(36) NOT NULL,
  `type` varchar(80) NOT NULL DEFAULT 'SQL_INJECTION',
  `ip_address` varchar(45) NOT NULL,
  `payload_hash` char(64) NOT NULL DEFAULT '',
  `payload_preview` varchar(500) DEFAULT NULL,
  `risk_score` decimal(5,2) NOT NULL DEFAULT 0.00,
  `ai_confidence` decimal(5,4) DEFAULT NULL,
  `ai_risk_factors` text DEFAULT NULL,
  `detection_method` varchar(50) NOT NULL DEFAULT 'WAF',
  `threat_level` enum('low','medium','high','critical') NOT NULL DEFAULT 'high',
  `action_taken` varchar(30) NOT NULL DEFAULT 'blocked',
  `blocked` tinyint(1) NOT NULL DEFAULT 1,
  `country_code` char(2) DEFAULT 'XX',
  `threat_type` varchar(80) NOT NULL DEFAULT 'SQL Injection',
  `subtype` varchar(80) DEFAULT NULL,
  `endpoint` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `city` varchar(100) DEFAULT NULL,
  `region` varchar(100) DEFAULT NULL,
  `http_method` varchar(10) DEFAULT NULL,
  `response_code` smallint unsigned DEFAULT NULL,
  `session_id` char(64) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `user_id` bigint unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_security_incidents_uuid` (`uuid`),
  KEY `idx_security_incidents_created_at` (`created_at`),
  KEY `idx_security_incidents_ip` (`ip_address`),
  KEY `idx_security_incidents_blocked` (`blocked`),
  KEY `idx_security_incidents_risk_score` (`risk_score`),
  KEY `idx_security_incidents_threat_level` (`threat_level`),
  KEY `idx_security_incidents_type` (`type`),
  KEY `idx_security_incidents_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- Table : ai_analysis_logs
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS `ai_analysis_logs`;
CREATE TABLE `ai_analysis_logs` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `request_id` varchar(32) NOT NULL,
  `analyzed_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ai_verdict` varchar(20) NOT NULL DEFAULT 'benign',
  `human_verdict` varchar(20) DEFAULT NULL,
  `processing_time_ms` decimal(10,2) DEFAULT NULL,
  `risk_score` decimal(5,4) DEFAULT NULL,
  `context` varchar(80) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_ai_analysis_analyzed_at` (`analyzed_at`),
  KEY `idx_ai_analysis_request_id` (`request_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- Table : rate_limits
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS `rate_limits`;
CREATE TABLE `rate_limits` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `key_hash` varchar(64) NOT NULL COMMENT 'Hash (IP ou user_id + endpoint)',
  `endpoint` varchar(120) NOT NULL,
  `count` int unsigned NOT NULL DEFAULT 0,
  `window_start` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_rate_limits_key_endpoint` (`key_hash`, `endpoint`),
  KEY `idx_rate_limits_window` (`window_start`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- Procédure : cleanup_old_incidents
-- -----------------------------------------------------------------------------
DROP PROCEDURE IF EXISTS `cleanup_old_incidents`;
DELIMITER ;;
CREATE PROCEDURE `cleanup_old_incidents`(IN retention_days INT)
BEGIN
  DELETE FROM security_incidents
  WHERE created_at < DATE_SUB(CURDATE(), INTERVAL retention_days DAY);
  SELECT ROW_COUNT() AS deleted_rows;
END;;
DELIMITER ;

-- -----------------------------------------------------------------------------
-- Procédure : get_user_security_stats
-- -----------------------------------------------------------------------------
DROP PROCEDURE IF EXISTS `get_user_security_stats`;
DELIMITER ;;
CREATE PROCEDURE `get_user_security_stats`(IN p_user_id INT UNSIGNED)
BEGIN
  SELECT
    u.id,
    u.username,
    u.email,
    u.role,
    u.last_login_at,
    u.login_attempts,
    u.locked_until,
    (SELECT COUNT(*) FROM security_incidents WHERE DATE(created_at) = CURDATE()) AS today_incidents,
    (SELECT COUNT(*) FROM ai_analysis_logs WHERE DATE(analyzed_at) = CURDATE()) AS today_ai_analyses
  FROM users u
  WHERE u.id = p_user_id AND u.deleted_at IS NULL;
END;;
DELIMITER ;

-- -----------------------------------------------------------------------------
-- Vue : daily_security_report
-- -----------------------------------------------------------------------------
DROP VIEW IF EXISTS `daily_security_report`;
CREATE VIEW `daily_security_report` AS
SELECT
  DATE(created_at) AS report_date,
  COUNT(*) AS total_incidents,
  SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) AS blocked_count,
  COUNT(DISTINCT ip_address) AS unique_ips,
  AVG(risk_score) AS avg_risk_score,
  threat_type
FROM security_incidents
WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
GROUP BY DATE(created_at), threat_type
ORDER BY report_date DESC, total_incidents DESC;

-- -----------------------------------------------------------------------------
-- Vue : threat_intelligence
-- -----------------------------------------------------------------------------
DROP VIEW IF EXISTS `threat_intelligence`;
CREATE VIEW `threat_intelligence` AS
SELECT
  ip_address,
  country_code,
  threat_type,
  COUNT(*) AS attack_count,
  MAX(created_at) AS last_seen,
  AVG(risk_score) AS avg_risk_score
FROM security_incidents
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY ip_address, country_code, threat_type
HAVING attack_count >= 1
ORDER BY attack_count DESC;

SET FOREIGN_KEY_CHECKS = 1;

-- =============================================================================
-- Fin du schéma
-- =============================================================================
