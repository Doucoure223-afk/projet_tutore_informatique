-- =============================================================================
-- Migration : Ajouter les colonnes manquantes à security_incidents
-- À exécuter dans phpMyAdmin (ou mysql) si le dashboard affiche 0 attaque
-- alors que des blocages ont eu lieu (erreur "Champ 'threat_type' ou 'status' inconnu").
-- =============================================================================

USE `mon_projet_securite`;

-- Ajout de threat_type si la table a été créée sans cette colonne.
-- Si vous avez l'erreur "Duplicate column name", la colonne existe déjà : ignorer.
ALTER TABLE `security_incidents`
  ADD COLUMN `threat_type` varchar(80) NOT NULL DEFAULT 'SQL Injection' AFTER `country_code`;

-- Ajout de status si la table a été créée sans cette colonne.
-- Si vous avez l'erreur "Duplicate column name", la colonne existe déjà : ignorer.
ALTER TABLE `security_incidents`
  ADD COLUMN `status` varchar(30) NOT NULL DEFAULT 'blocked' AFTER `risk_score`;
