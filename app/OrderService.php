<?php
declare(strict_types=1);
require_once __DIR__ . '/StoreMoney.php';

/** Commandes persistantes ; les montants et le stock viennent toujours du catalogue. */
final class OrderService
{
    private mysqli $connection;

    public function __construct(mysqli $connection) { $this->connection = $connection; }

    public function schemaInstalled(): bool
    {
        try {
            $this->query('SELECT id, reference, payment_amount, status FROM commerce_orders LIMIT 0');
            $this->query('SELECT order_id, unit_price_cents, quantity FROM commerce_order_items LIMIT 0');
            return true;
        } catch (mysqli_sql_exception $exception) {
            if (in_array($exception->getCode(), [1146, 1054], true)) { return false; }
            throw $exception;
        }
    }

    /** 1 EUR = 655,957 XOF ; le guichet CinetPay exige un multiple de 5 XOF. */
    public static function amountInXof(int $totalCents): int
    {
        if ($totalCents < 1 || $totalCents > 100000000) {
            throw new InvalidArgumentException('Le montant de la commande est hors limites.');
        }
        return StoreMoney::fromEuroCents($totalCents);
    }

    public static function priceInCents(string $price): int
    {
        if (!preg_match('/^(\d{1,8})(?:\.(\d{1,2}))?$/D', $price, $matches)) {
            throw new InvalidArgumentException('Prix du catalogue invalide.');
        }
        return (int) $matches[1] * 100 + (int) str_pad($matches[2] ?? '', 2, '0');
    }

    public static function validReference(string $reference): bool
    {
        return (bool) preg_match('/^CS[A-F0-9]{32}$/D', $reference);
    }

    /**
     * Les valeurs name/price fournies par le panier ne font jamais autorité.
     * Un même jeton conserve la même commande même après un double clic.
     */
    public function createPending(int $userId, array $cartItems, string $checkoutToken, array $customer = []): array
    {
        if ($userId <= 0 || !preg_match('/^[a-f0-9]{64}$/iD', $checkoutToken)) {
            throw new InvalidArgumentException('Session de commande invalide.');
        }
        $tokenHash = hash('sha256', $checkoutToken);
        $this->connection->begin_transaction();
        try {
            // Serialize les créations du même compte avant de tester l'idempotence.
            $user = $this->query('SELECT id, username, email FROM users WHERE id = ? AND active = 1 FOR UPDATE', [$userId])->fetch_assoc();
            if (!$user) { throw new RuntimeException('Compte indisponible.'); }
            $existing = $this->query('SELECT * FROM commerce_orders WHERE user_id = ? AND checkout_token_hash = ? FOR UPDATE', [$userId, $tokenHash])->fetch_assoc();
            if ($existing) { $this->connection->commit(); return $existing; }
            if (!$cartItems || count($cartItems) > 100) {
                throw new InvalidArgumentException('Le panier doit contenir entre 1 et 100 articles distincts.');
            }
            $quantities = [];
            foreach ($cartItems as $item) {
                if (!is_array($item)) { throw new InvalidArgumentException('Article invalide.'); }
                $id = filter_var($item['id'] ?? null, FILTER_VALIDATE_INT);
                $quantity = filter_var($item['qty'] ?? null, FILTER_VALIDATE_INT);
                if (!$id || $id <= 0 || !$quantity || $quantity < 1 || $quantity > 99 || isset($quantities[$id])) {
                    throw new InvalidArgumentException('Article ou quantité invalide.');
                }
                $quantities[$id] = $quantity;
            }
            ksort($quantities, SORT_NUMERIC);
            $lines = [];
            $total = 0;
            $amount = 0;
            foreach ($quantities as $id => $quantity) {
                $product = $this->query('SELECT id, name, price, stock FROM products WHERE id = ? FOR UPDATE', [$id])->fetch_assoc();
                if (!$product || (int) $product['stock'] < $quantity) {
                    throw new RuntimeException('Le stock a changé. Revenez au panier pour vérifier les quantités.');
                }
                $price = self::priceInCents((string) $product['price']);
                $line = $price * $quantity;
                $total += $line;
                $snapshot = ['product_id' => $id, 'name' => $product['name'], 'unit_price_cents' => $price, 'quantity' => $quantity, 'line_total_cents' => $line];
                $amount += StoreMoney::orderLine($snapshot);
                $lines[] = $snapshot;
            }
            if ($total < 1 || $total > StoreMoney::MAX_EURO_CENTS) {
                throw new InvalidArgumentException('Le montant de la commande est hors limites.');
            }
            $customer = self::customerSnapshot($customer, $user);
            $reference = 'CS' . strtoupper(bin2hex(random_bytes(16)));
            $this->query('INSERT INTO commerce_orders (reference, user_id, checkout_token_hash, total_cents, payment_amount, customer_name, customer_email, customer_phone, customer_address, customer_city, customer_country, customer_zip_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [
                $reference, $userId, $tokenHash, $total, $amount, $customer['name'], $customer['email'], $customer['phone'], $customer['address'], $customer['city'], $customer['country'], $customer['zip_code'],
            ]);
            $orderId = (int) $this->connection->insert_id;
            foreach ($lines as $line) {
                $this->query('INSERT INTO commerce_order_items (order_id, product_id, name, unit_price_cents, quantity, line_total_cents) VALUES (?, ?, ?, ?, ?, ?)', [$orderId, $line['product_id'], $line['name'], $line['unit_price_cents'], $line['quantity'], $line['line_total_cents']]);
            }
            $order = $this->query('SELECT * FROM commerce_orders WHERE id = ?', [$orderId])->fetch_assoc();
            $this->connection->commit();
            return $order;
        } catch (Throwable $exception) {
            $this->connection->rollback();
            throw $exception;
        }
    }

    public function findForUser(string $reference, int $userId): ?array
    {
        if (!self::validReference($reference) || $userId < 1) { return null; }
        return $this->query('SELECT * FROM commerce_orders WHERE reference = ? AND user_id = ?', [$reference, $userId])->fetch_assoc() ?: null;
    }

    public function listForUser(int $userId, int $limit = 10): array
    {
        return $this->query('SELECT * FROM commerce_orders WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?', [$userId, max(1, min(50, $limit))])->fetch_all(MYSQLI_ASSOC);
    }

    /** Appeler après findForUser ; un identifiant interne ne doit jamais être accepté depuis l'URL. */
    public function items(int $orderId): array
    {
        return $this->query('SELECT product_id, name, unit_price_cents, quantity, line_total_cents FROM commerce_order_items WHERE order_id = ? ORDER BY id', [$orderId])->fetch_all(MYSQLI_ASSOC);
    }

    public function attachCheckout(int $orderId, string $paymentUrl): void
    {
        if (!class_exists('CinetPay', false)) { require_once __DIR__ . '/CinetPay.php'; }
        if (!CinetPay::validCheckoutUrl($paymentUrl)) { throw new InvalidArgumentException('Adresse de paiement invalide.'); }
        $this->query("UPDATE commerce_orders SET payment_url = ? WHERE id = ? AND status = 'pending'", [$paymentUrl, $orderId]);
    }

    /** Réservé au webhook après HMAC et interrogation serveur à serveur. */
    public function reconcilePayment(string $reference, array $verification): array
    {
        if (!self::validReference($reference)) { throw new InvalidArgumentException('Référence invalide.'); }
        $this->connection->begin_transaction();
        try {
            $order = $this->query('SELECT * FROM commerce_orders WHERE reference = ? FOR UPDATE', [$reference])->fetch_assoc();
            if (!$order) { throw new OutOfBoundsException('Commande inconnue.'); }
            // Une notification tardive ne peut ni annuler ni débiter deux fois une commande payée.
            if (in_array($order['status'], ['paid', 'paid_review'], true)) {
                $this->connection->commit();
                return $order;
            }
            $amount = (string) ($verification['amount'] ?? '');
            if (!preg_match('/^\d+(?:\.0{1,2})?$/D', $amount) ||
                (int) $amount !== (int) $order['payment_amount'] ||
                ($verification['currency'] ?? '') !== $order['payment_currency']) {
                throw new UnexpectedValueException('Le montant vérifié ne correspond pas à la commande.');
            }
            $status = (string) ($verification['status'] ?? '');
            if ($status === 'ACCEPTED' && ($verification['code'] ?? '') === '00') {
                $lines = $this->query('SELECT product_id, quantity FROM commerce_order_items WHERE order_id = ? ORDER BY product_id', [(int) $order['id']])->fetch_all(MYSQLI_ASSOC);
                $stockAvailable = count($lines) > 0;
                foreach ($lines as $line) {
                    $product = $this->query('SELECT id, stock FROM products WHERE id = ? FOR UPDATE', [(int) $line['product_id']])->fetch_assoc();
                    if (!$product || (int) $product['stock'] < (int) $line['quantity']) { $stockAvailable = false; }
                }
                if ($stockAvailable) {
                    foreach ($lines as $line) {
                        $this->query('UPDATE products SET stock = stock - ? WHERE id = ?', [(int) $line['quantity'], (int) $line['product_id']]);
                    }
                }
                $nextStatus = $stockAvailable ? 'paid' : 'paid_review';
                $this->query('UPDATE commerce_orders SET status = ?, paid_at = CURRENT_TIMESTAMP WHERE id = ?', [$nextStatus, (int) $order['id']]);
            } elseif ($status === 'REFUSED') {
                $this->query("UPDATE commerce_orders SET status = 'payment_failed' WHERE id = ?", [(int) $order['id']]);
            }
            // WAITING_FOR_CUSTOMER et tout statut intermédiaire restent en attente.
            $order = $this->query('SELECT * FROM commerce_orders WHERE id = ?', [(int) $order['id']])->fetch_assoc();
            $this->connection->commit();
            return $order;
        } catch (Throwable $exception) {
            $this->connection->rollback();
            throw $exception;
        }
    }

    private static function customerSnapshot(array $customer, array $user): array
    {
        $limits = ['name' => 100, 'email' => 100, 'phone' => 32, 'address' => 200, 'city' => 80, 'country' => 2, 'zip_code' => 20];
        $customer += ['name' => $user['username'], 'email' => $user['email'], 'country' => 'ML'];
        $snapshot = [];
        foreach ($limits as $key => $limit) {
            $value = $customer[$key] ?? '';
            if (!is_string($value) || preg_match('/[\x00-\x1F\x7F]/', $value) || mb_strlen($value) > $limit) {
                throw new InvalidArgumentException('Coordonnées de commande invalides.');
            }
            $snapshot[$key] = trim($value);
        }
        $snapshot['country'] = strtoupper($snapshot['country']);
        if ($snapshot['name'] === '' || !filter_var($snapshot['email'], FILTER_VALIDATE_EMAIL) || !preg_match('/^[A-Z]{2}$/D', $snapshot['country'])) {
            throw new InvalidArgumentException('Vérifiez votre nom, votre adresse courriel et votre pays.');
        }
        return $snapshot;
    }

    private function query(string $sql, array $parameters = []): mysqli_result|bool
    {
        $statement = $this->connection->prepare($sql);
        try {
            if ($parameters) {
                $types = implode('', array_map(static fn($value) => is_int($value) ? 'i' : 's', $parameters));
                $statement->bind_param($types, ...$parameters);
            }
            $statement->execute();
            return $statement->field_count ? $statement->get_result() : true;
        } finally { $statement->close(); }
    }
}
