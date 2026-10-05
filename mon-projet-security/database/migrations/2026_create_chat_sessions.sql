-- Sessions de chat (conversations) pour l'historique
USE `mon_projet_securite`;

CREATE TABLE IF NOT EXISTS `chat_sessions` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int unsigned NOT NULL,
  `title` varchar(255) NOT NULL DEFAULT 'Conversation',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_chat_sessions_user` (`user_id`),
  KEY `idx_chat_sessions_created` (`created_at` DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Sessions (conversations) du chat assistant';

-- Ajouter session_id à chat_messages (exécuter une seule fois ; ignorer l'erreur si la colonne existe déjà)
ALTER TABLE `chat_messages`
  ADD COLUMN `session_id` int unsigned NULL DEFAULT NULL AFTER `user_id`,
  ADD KEY `idx_chat_messages_session` (`session_id`);
