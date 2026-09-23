-- Données de démo pour projet_sqli_vulnerable
-- À exécuter dans phpMyAdmin ou MySQL
-- Concordance avec mon-projet-security pour la démo

USE projet_sqli_vulnerable;

-- Créer la table products si elle n'existe pas
CREATE TABLE IF NOT EXISTS `products` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `category` varchar(100) DEFAULT NULL,
  `price` decimal(10,2) NOT NULL DEFAULT 0.00,
  `stock` int unsigned NOT NULL DEFAULT 0,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_products_name` (`name`),
  KEY `idx_products_category` (`category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Vider et réinsérer les mêmes produits que mon-projet-security
DELETE FROM `products`;
INSERT INTO `products` (`name`, `description`, `category`, `price`, `stock`) VALUES
('Smartphone Pro', 'Téléphone haut de gamme 5G', 'Électronique', 899.00, 15),
('Écouteurs Bluetooth', 'Casque sans fil avec réduction de bruit', 'Électronique', 149.00, 50),
('Laptop Ultra', 'Ordinateur portable 15 pouces', 'Électronique', 1299.00, 8),
('Montre Connectée', 'Suivi fitness et notifications', 'Électronique', 299.00, 25),
('Clavier Mécanique', 'Rétroéclairage RGB', 'Accessoires', 89.00, 40),
('Souris Ergo', 'Confort et précision', 'Accessoires', 59.00, 60),
('Webcam HD', 'Streaming 1080p', 'Accessoires', 79.00, 30),
('Chargeur Sans Fil', 'Charge rapide 15W', 'Accessoires', 45.00, 100);

-- Compte de test recommandé (créer si nécessaire)
-- INSERT INTO users (username, password, email, role, created_at) 
-- VALUES ('demo', 'demo123', 'demo@test.local', 'user', NOW())
-- ON DUPLICATE KEY UPDATE password = 'demo123';
