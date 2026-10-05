-- =============================================================================
-- Migration : ajouter les colonnes manquantes à la table users
-- À exécuter dans phpMyAdmin (ou mysql) si vous avez l'erreur "mfa_enabled inconnu"
-- Si une colonne existe déjà, MySQL affichera "Duplicate column" : ignorez cette ligne.
-- =============================================================================

USE `mon_projet_securite`;

-- Colonne qui provoque l'erreur actuelle
ALTER TABLE `users` ADD COLUMN `mfa_enabled` TINYINT(1) NOT NULL DEFAULT 0;

-- Autres colonnes éventuellement manquantes (décommenter si erreur "Column not found")
-- ALTER TABLE `users` ADD COLUMN `login_attempts` INT UNSIGNED NOT NULL DEFAULT 0 AFTER `role`;
-- ALTER TABLE `users` ADD COLUMN `locked_until` DATETIME DEFAULT NULL AFTER `login_attempts`;
-- ALTER TABLE `users` ADD COLUMN `last_login_at` DATETIME DEFAULT NULL AFTER `mfa_enabled`;
-- ALTER TABLE `users` ADD COLUMN `deleted_at` DATETIME DEFAULT NULL AFTER `last_login_at`;
-- ALTER TABLE `users` ADD COLUMN `verification_token` VARCHAR(64) DEFAULT NULL AFTER `deleted_at`;
-- ALTER TABLE `users` ADD COLUMN `email_verified_at` DATETIME DEFAULT NULL AFTER `verification_token`;
