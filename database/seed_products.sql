-- CyberShield AI : données fictives ajoutées uniquement si absentes.
-- Ne supprime ni ne remplace les produits, comptes ou mots de passe existants.
USE projet_sqli_vulnerable;
SET NAMES utf8mb4;

INSERT INTO products (name, description, category, price, stock)
SELECT seed.name, seed.description, seed.category, seed.price, seed.stock
FROM (
  SELECT 'Smartphone Pro' AS name, 'Téléphone haut de gamme 5G' AS description, 'Électronique' AS category, 899.00 AS price, 15 AS stock
  UNION ALL SELECT 'Écouteurs Bluetooth', 'Casque sans fil avec réduction de bruit', 'Électronique', 149.00, 50
  UNION ALL SELECT 'Laptop Ultra', 'Ordinateur portable 15 pouces', 'Électronique', 1299.00, 8
  UNION ALL SELECT 'Montre Connectée', 'Suivi fitness et notifications', 'Électronique', 299.00, 25
  UNION ALL SELECT 'Clavier Mécanique', 'Rétroéclairage RGB', 'Accessoires', 89.00, 40
  UNION ALL SELECT 'Souris Ergo', 'Confort et précision', 'Accessoires', 59.00, 60
  UNION ALL SELECT 'Webcam HD', 'Streaming 1080p', 'Accessoires', 79.00, 30
  UNION ALL SELECT 'Chargeur Sans Fil', 'Charge rapide 15W', 'Accessoires', 45.00, 100
) AS seed
WHERE NOT EXISTS (SELECT 1 FROM products WHERE products.name = seed.name);

-- Comptes fictifs du laboratoire local, mots de passe hachés avec bcrypt :
-- cybershield_admin / CyberShieldDemo!2026
-- cybershield_client / DemoClient!2026
INSERT INTO users (username, password, email, role)
SELECT 'cybershield_admin', '$2y$12$aHIuiYQmGh2dqBn8EPe/HepimOWeodYAGlo9mzuOPn7.mkP5/WM4W', 'admin@cybershield.test', 'admin'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'cybershield_admin' OR email = 'admin@cybershield.test');

INSERT INTO users (username, password, email, role)
SELECT 'cybershield_client', '$2y$12$eA9CLyw.JMOIsw0a90FWZuKK6n2rtpuxake134hpqp4YBdopqX4qS', 'client@cybershield.test', 'user'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'cybershield_client' OR email = 'client@cybershield.test');
