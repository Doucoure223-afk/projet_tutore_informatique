-- Table products pour la page de recherche sécurisée
-- Concordance avec projet_tutoré_inf pour la démo vulnérable vs sécurisé

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

-- Données de démo (concordance avec projet vulnérable)
INSERT INTO `products` (`name`, `description`, `category`, `price`, `stock`) VALUES
('Smartphone Pro', 'Téléphone haut de gamme 5G', 'Électronique', 899.00, 15),
('Écouteurs Bluetooth', 'Casque sans fil avec réduction de bruit', 'Électronique', 149.00, 50),
('Laptop Ultra', 'Ordinateur portable 15 pouces', 'Électronique', 1299.00, 8),
('Montre Connectée', 'Suivi fitness et notifications', 'Électronique', 299.00, 25),
('Clavier Mécanique', 'Rétroéclairage RGB', 'Accessoires', 89.00, 40),
('Souris Ergo', 'Confort et précision', 'Accessoires', 59.00, 60),
('Webcam HD', 'Streaming 1080p', 'Accessoires', 79.00, 30),
('Chargeur Sans Fil', 'Charge rapide 15W', 'Accessoires', 45.00, 100);
