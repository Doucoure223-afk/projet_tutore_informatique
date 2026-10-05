-- =============================================================================
-- Migration : Colonne explicabilité IA (facteurs de risque par incident)
-- ai_confidence existe déjà ; on n'ajoute que ai_risk_factors.
-- =============================================================================

USE `mon_projet_securite`;

-- Facteurs de risque (explicabilité) : JSON des top features qui ont contribué
-- En cas d'erreur "Duplicate column", la colonne existe déjà : ignorer.
ALTER TABLE `security_incidents`
  ADD COLUMN `ai_risk_factors` TEXT NULL DEFAULT NULL
  COMMENT 'JSON: top facteurs IA (ex. liste de chaînes)'
  AFTER `ai_confidence`;
