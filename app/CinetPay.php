<?php
declare(strict_types=1);

/** Checkout hébergé v2. Désactivé par défaut ; tests avec transport injecté. */
final class CinetPay
{
    private const ENDPOINT = 'https://api-checkout.cinetpay.com/v2/payment';
    private const MAX_RESPONSE_BYTES = 65536;
    private const SIGNED_FIELDS = [
        'cpm_site_id', 'cpm_trans_id', 'cpm_trans_date', 'cpm_amount', 'cpm_currency',
        'signature', 'payment_method', 'cel_phone_num', 'cpm_phone_prefixe', 'cpm_language',
        'cpm_version', 'cpm_payment_config', 'cpm_page_action', 'cpm_custom', 'cpm_designation', 'cpm_error_message',
    ];
    private array $configuration;
    private ?Closure $transport;

    public function __construct(array $configuration, ?callable $transport = null)
    {
        $this->configuration = $configuration;
        $this->transport = $transport === null ? null : Closure::fromCallable($transport);
    }

    public static function fromEnvironment(): self
    {
        return new self([
            'enabled' => filter_var(getenv('PAYMENT_ENABLED') ?: 'false', FILTER_VALIDATE_BOOLEAN),
            'api_key' => self::environmentSecret('CINETPAY_API_KEY'),
            'site_id' => getenv('CINETPAY_SITE_ID') ?: '',
            'secret_key' => self::environmentSecret('CINETPAY_SECRET_KEY'),
            'public_url' => rtrim(getenv('APP_PUBLIC_URL') ?: '', '/'),
        ]);
    }

    public function isReady(): bool
    {
        return filter_var($this->configuration['enabled'] ?? false, FILTER_VALIDATE_BOOLEAN)
            && $this->credentialsValid()
            && self::validPublicUrl($this->publicBaseUrl());
    }

    public function unavailableReason(): string
    {
        if (!filter_var($this->configuration['enabled'] ?? false, FILTER_VALIDATE_BOOLEAN)) { return 'Le paiement en ligne n’est pas encore activé.'; }
        if (!$this->credentialsValid()) {
            return 'La configuration du compte marchand CinetPay est incomplète.';
        }
        if (!self::validPublicUrl((string) ($this->configuration['public_url'] ?? ''))) {
            return 'Une adresse publique HTTPS est nécessaire pour recevoir la confirmation du paiement.';
        }
        return 'Le service de paiement est momentanément indisponible.';
    }

    public function publicBaseUrl(): string { return rtrim((string) ($this->configuration['public_url'] ?? ''), '/'); }

    public static function validPublicUrl(string $url): bool
    {
        $parts = parse_url($url);
        if (!$parts || ($parts['scheme'] ?? '') !== 'https' || !isset($parts['host']) ||
            isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment']) ||
            (isset($parts['port']) && $parts['port'] !== 443) || !in_array($parts['path'] ?? '', ['', '/'], true)) { return false; }
        $host = strtolower($parts['host']);
        if ($host === 'localhost' || !str_contains($host, '.') || preg_match('/\.(?:localhost|local|test|invalid)$/D', $host)) { return false; }
        if (filter_var(trim($host, '[]'), FILTER_VALIDATE_IP)) {
            return (bool) filter_var(trim($host, '[]'), FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        }
        return (bool) filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
    }

    public static function validCheckoutUrl(string $url): bool
    {
        if (strlen($url) > 512) { return false; }
        $parts = parse_url($url);
        return $parts && ($parts['scheme'] ?? '') === 'https' &&
            strtolower($parts['host'] ?? '') === 'checkout.cinetpay.com' &&
            !isset($parts['user']) && !isset($parts['pass']) && !isset($parts['fragment']) && !isset($parts['query']) &&
            (!isset($parts['port']) || $parts['port'] === 443) &&
            (bool) preg_match('~^/payment/[A-Za-z0-9-]{16,256}$~D', $parts['path'] ?? '');
    }

    public function startCheckout(array $order, array $customer = []): array
    {
        $this->requireReady();
        $reference = $order['reference'] ?? '';
        $amount = $order['payment_amount'] ?? null;
        if (!is_string($reference) || !preg_match('/^CS[A-F0-9]{32}$/D', $reference)
            || !is_int($amount) && !(is_string($amount) && ctype_digit($amount))
            || (int) $amount < 5 || (int) $amount > 655957000 || (int) $amount % 5 !== 0
            || ($order['payment_currency'] ?? '') !== 'XOF'
            || !in_array($order['status'] ?? '', ['pending', 'payment_failed'], true)) {
            throw new InvalidArgumentException('Commande non payable.');
        }
        // Mobile Money uniquement : aucune coordonnée client n’est envoyée.
        // Le client renseigne ses informations de règlement chez le prestataire.
        $response = $this->request('', [
            'apikey' => $this->configuration['api_key'],
            'site_id' => (string) $this->configuration['site_id'],
            'transaction_id' => $reference,
            'amount' => (int) $amount,
            'currency' => 'XOF',
            'description' => 'Commande CyberShield',
            'notify_url' => $this->publicBaseUrl() . '/app/payment-notify.php',
            'return_url' => $this->publicBaseUrl() . '/app/paiement.php?order=' . $reference,
            'channels' => 'MOBILE_MONEY',
            'metadata' => $reference,
            'lang' => 'fr',
        ]);
        $url = $response['data']['payment_url'] ?? null;
        if (($response['code'] ?? '') !== '201' || !is_string($url) || !self::validCheckoutUrl($url)) {
            throw new RuntimeException('Le prestataire n’a pas confirmé l’ouverture du guichet.');
        }
        return ['payment_url' => $url];
    }

    /** Validation cryptographique locale seulement, aucun statut financier n'en découle. */
    public function verifyNotification(array $posted, string $receivedToken): string
    {
        $secret = (string) ($this->configuration['secret_key'] ?? '');
        if ($secret === '' || !preg_match('/^[a-f0-9]{64}$/iD', $receivedToken)) {
            throw new UnexpectedValueException('Notification non authentifiée.');
        }
        $data = '';
        foreach (self::SIGNED_FIELDS as $field) {
            $value = $posted[$field] ?? '';
            if (!is_string($value) || strlen($value) > 4096) { throw new UnexpectedValueException('Notification invalide.'); }
            $data .= $value;
        }
        $expected = hash_hmac('sha256', $data, $secret);
        $reference = $posted['cpm_trans_id'] ?? '';
        if (!hash_equals($expected, strtolower($receivedToken)) ||
            ($posted['cpm_site_id'] ?? '') !== (string) ($this->configuration['site_id'] ?? '') ||
            !preg_match('/^CS[A-F0-9]{32}$/D', $reference)) {
            throw new UnexpectedValueException('Notification non authentifiée.');
        }
        return $reference;
    }

    /** Les identifiants sont ceux de la requête serveur, jamais ceux d’un retour navigateur. */
    public function checkTransaction(string $reference): array
    {
        $this->requireReady();
        if (!preg_match('/^CS[A-F0-9]{32}$/D', $reference)) { throw new InvalidArgumentException('Référence invalide.'); }
        $response = $this->request('/check', [
            'apikey' => $this->configuration['api_key'],
            'site_id' => (string) $this->configuration['site_id'],
            'transaction_id' => $reference,
        ]);
        $data = $response['data'] ?? null;
        if (!is_array($data) || !is_string($response['code'] ?? null)
            || !in_array($data['status'] ?? '', ['ACCEPTED', 'REFUSED', 'WAITING_FOR_CUSTOMER'], true)
            || !is_scalar($data['amount'] ?? null)
            || !preg_match('/^[0-9]{1,10}(?:\.0{1,2})?$/D', (string) $data['amount'])
            || ($data['currency'] ?? '') !== 'XOF'
            || (($data['status'] ?? '') === 'ACCEPTED' && $response['code'] !== '00')) {
            throw new UnexpectedValueException('Vérification financière non concluante.');
        }
        foreach (['transaction_id' => $reference, 'site_id' => (string) $this->configuration['site_id'], 'metadata' => $reference] as $key => $expected) {
            if (isset($data[$key]) && $data[$key] !== ''
                && (!is_string($data[$key]) || $data[$key] !== $expected)) {
                throw new UnexpectedValueException('Vérification liée à une autre transaction.');
            }
        }
        return ['code' => $response['code'], 'amount' => (string) $data['amount'],
            'currency' => 'XOF', 'status' => $data['status'], 'reference' => $reference];
    }

    private function credentialsValid(): bool
    {
        foreach (['api_key', 'secret_key'] as $key) {
            $value = $this->configuration[$key] ?? null;
            if (!is_string($value) || $value === '' || strlen($value) > 4096 || preg_match('/[\x00-\x20\x7F]/', $value)) { return false; }
        }
        return is_string($this->configuration['site_id'] ?? null)
            && (bool) preg_match('/^[0-9]{1,20}$/D', $this->configuration['site_id']);
    }

    private function requireReady(): void
    {
        if (!$this->isReady()) { throw new RuntimeException($this->unavailableReason()); }
    }

    private function request(string $suffix, array $payload): array
    {
        $body = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $url = self::ENDPOINT . $suffix;
        if ($this->transport !== null) {
            $result = ($this->transport)($url, $body);
        } else {
            if (!extension_loaded('curl')) { throw new RuntimeException('Transport de paiement indisponible.'); }
            $curl = curl_init($url);
            $responseBody = '';
            curl_setopt_array($curl, [
                CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body,
                CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json'],
                CURLOPT_CONNECTTIMEOUT_MS => 2500, CURLOPT_TIMEOUT_MS => 10000,
                CURLOPT_FOLLOWLOCATION => false, CURLOPT_MAXREDIRS => 0,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROXY => '', CURLOPT_NOSIGNAL => true,
                CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$responseBody): int {
                    if (strlen($responseBody) + strlen($chunk) > self::MAX_RESPONSE_BYTES) { return 0; }
                    $responseBody .= $chunk;
                    return strlen($chunk);
                },
            ]);
            try {
                $success = curl_exec($curl);
                $result = ['status' => curl_getinfo($curl, CURLINFO_HTTP_CODE), 'body' => $responseBody];
                if ($success === false) { throw new RuntimeException('Le prestataire ne répond pas.'); }
            } finally { curl_close($curl); }
        }
        if (!is_array($result) || ($result['status'] ?? 0) !== 200
            || !is_string($result['body'] ?? null) || strlen($result['body']) > self::MAX_RESPONSE_BYTES) {
            throw new RuntimeException('Réponse du prestataire indisponible.');
        }
        try { $decoded = json_decode($result['body'], true, 16, JSON_THROW_ON_ERROR); }
        catch (JsonException $error) { throw new RuntimeException('Réponse du prestataire invalide.'); }
        if (!is_array($decoded)) { throw new RuntimeException('Réponse du prestataire invalide.'); }
        return $decoded;
    }

    private static function environmentSecret(string $name): string
    {
        $file = getenv($name . '_FILE');
        if (is_string($file) && $file !== '') {
            if (!is_file($file) || !is_readable($file) || filesize($file) > 4096) { return ''; }
            $value = @file_get_contents($file);
            return is_string($value) ? trim($value) : '';
        }
        $value = getenv($name);
        return is_string($value) && strlen($value) <= 4096 ? trim($value) : '';
    }
}
