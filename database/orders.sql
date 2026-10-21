-- Migration additive : aucune modification des anciennes commandes ni du catalogue.
-- À exécuter dans la base applicative existante, avec un compte de migration.
CREATE TABLE IF NOT EXISTS commerce_orders (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  reference CHAR(34) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  user_id INT NOT NULL,
  checkout_token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  total_cents BIGINT UNSIGNED NOT NULL,
  currency CHAR(3) NOT NULL DEFAULT 'EUR',
  payment_amount BIGINT UNSIGNED NOT NULL,
  payment_currency CHAR(3) NOT NULL DEFAULT 'XOF',
  status ENUM('pending', 'paid', 'payment_failed', 'paid_review') NOT NULL DEFAULT 'pending',
  payment_url VARCHAR(512) DEFAULT NULL,
  customer_name VARCHAR(100) NOT NULL,
  customer_email VARCHAR(100) NOT NULL,
  customer_phone VARCHAR(32) NOT NULL DEFAULT '',
  customer_address VARCHAR(200) NOT NULL DEFAULT '',
  customer_city VARCHAR(80) NOT NULL DEFAULT '',
  customer_country CHAR(2) NOT NULL DEFAULT 'ML',
  customer_zip_code VARCHAR(20) NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  paid_at DATETIME DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_commerce_reference (reference),
  UNIQUE KEY uq_commerce_checkout (user_id, checkout_token_hash),
  KEY idx_commerce_user_created (user_id, created_at),
  CONSTRAINT fk_commerce_order_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS commerce_order_items (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  order_id BIGINT UNSIGNED NOT NULL,
  product_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  unit_price_cents BIGINT UNSIGNED NOT NULL,
  quantity SMALLINT UNSIGNED NOT NULL,
  line_total_cents BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_commerce_order_product (order_id, product_id),
  CONSTRAINT fk_commerce_item_order FOREIGN KEY (order_id) REFERENCES commerce_orders (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
