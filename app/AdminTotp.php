<?php
declare(strict_types=1);

/** RFC 6238 TOTP for administrator sign-in, with an encrypted server-side secret. */
final class AdminTotp
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function generateSecret(): string
    {
        return self::base32Encode(random_bytes(20));
    }

    public static function provisioningUri(string $secret, string $account): string
    {
        $issuer = 'CyberShield AI';
        return 'otpauth://totp/' . rawurlencode($issuer . ':' . $account)
            . '?secret=' . rawurlencode($secret)
            . '&issuer=' . rawurlencode($issuer)
            . '&algorithm=SHA1&digits=6&period=30';
    }

    public static function codeAt(string $secret, ?int $timestamp = null): string
    {
        $timestamp ??= time();
        if ($timestamp < 0) {
            throw new InvalidArgumentException('Horodatage TOTP invalide.');
        }
        $counter = intdiv($timestamp, 30);
        $binaryCounter = pack('N2', intdiv($counter, 4294967296), $counter & 0xffffffff);
        $digest = hash_hmac('sha1', $binaryCounter, self::base32Decode($secret), true);
        $offset = ord($digest[strlen($digest) - 1]) & 0x0f;
        $value = unpack('Nvalue', substr($digest, $offset, 4))['value'] & 0x7fffffff;
        return sprintf('%06d', $value % 1000000);
    }

    public static function verify(string $secret, string $code, ?int $timestamp = null): bool
    {
        if (preg_match('/^\d{6}$/D', $code) !== 1) {
            return false;
        }
        $timestamp ??= time();
        foreach ([-30, 0, 30] as $drift) {
            if ($timestamp + $drift >= 0 && hash_equals(self::codeAt($secret, $timestamp + $drift), $code)) {
                return true;
            }
        }
        return false;
    }

    public static function encrypt(string $secret): string
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('OpenSSL est nécessaire pour protéger la clé MFA.');
        }
        $nonce = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($secret, 'aes-256-gcm', self::encryptionKey(), OPENSSL_RAW_DATA, $nonce, $tag);
        if ($ciphertext === false || strlen($tag) !== 16) {
            throw new RuntimeException('Chiffrement de la clé MFA impossible.');
        }
        return 'v1.' . base64_encode($nonce . $tag . $ciphertext);
    }

    public static function decrypt(string $encrypted): string
    {
        if (!extension_loaded('openssl') || !str_starts_with($encrypted, 'v1.')) {
            throw new RuntimeException('Clé MFA invalide ou format non pris en charge.');
        }
        $payload = base64_decode(substr($encrypted, 3), true);
        if ($payload === false || strlen($payload) < 29) {
            throw new RuntimeException('Clé MFA invalide.');
        }
        $secret = openssl_decrypt(
            substr($payload, 28),
            'aes-256-gcm',
            self::encryptionKey(),
            OPENSSL_RAW_DATA,
            substr($payload, 0, 12),
            substr($payload, 12, 16)
        );
        if ($secret === false) {
            throw new RuntimeException('Déchiffrement de la clé MFA impossible.');
        }
        return $secret;
    }

    private static function base32Encode(string $bytes): string
    {
        $output = '';
        $buffer = 0;
        $bits = 0;
        foreach (unpack('C*', $bytes) as $byte) {
            $buffer = ($buffer << 8) | $byte;
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $output .= self::ALPHABET[($buffer >> $bits) & 31];
                $buffer &= (1 << $bits) - 1;
            }
        }
        if ($bits > 0) {
            $output .= self::ALPHABET[($buffer << (5 - $bits)) & 31];
        }
        return $output;
    }

    private static function base32Decode(string $secret): string
    {
        $secret = strtoupper(rtrim(str_replace('=', '', trim($secret)), '='));
        if ($secret === '' || preg_match('/^[A-Z2-7]+$/D', $secret) !== 1) {
            throw new InvalidArgumentException('Clé TOTP invalide.');
        }
        $buffer = 0;
        $bits = 0;
        $output = '';
        for ($i = 0, $length = strlen($secret); $i < $length; $i++) {
            $value = strpos(self::ALPHABET, $secret[$i]);
            if ($value === false) {
                throw new InvalidArgumentException('Clé TOTP invalide.');
            }
            $buffer = ($buffer << 5) | $value;
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $output .= chr(($buffer >> $bits) & 0xff);
                $buffer &= (1 << $bits) - 1;
            }
        }
        return $output;
    }

    private static function encryptionKey(): string
    {
        $directory = getenv('CYBERSHIELD_LOG_DIR') ?: __DIR__ . '/../logs';
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Dossier privé des clés inaccessible.');
        }
        $path = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR . 'admin-mfa.key';
        $lockPath = $path . '.lock';
        $lock = @fopen($lockPath, 'c+');
        if ($lock === false) {
            throw new RuntimeException('Verrou de la clé MFA inaccessible.');
        }
        @chmod($lockPath, 0600);
        try {
            if (!flock($lock, LOCK_EX)) {
                throw new RuntimeException('Verrou de la clé MFA indisponible.');
            }
            if (!is_file($path)) {
                $temporary = tempnam($directory, '.admin-mfa-');
                if ($temporary === false) {
                    throw new RuntimeException('Création de la clé MFA impossible.');
                }
                try {
                    if (file_put_contents($temporary, random_bytes(32), LOCK_EX) !== 32) {
                        throw new RuntimeException('Écriture de la clé MFA impossible.');
                    }
                    @chmod($temporary, 0600);
                    if (!@rename($temporary, $path)) {
                        throw new RuntimeException('Enregistrement de la clé MFA impossible.');
                    }
                } finally {
                    if (is_file($temporary)) {
                        @unlink($temporary);
                    }
                }
            }
            $key = @file_get_contents($path);
            if (!is_string($key) || strlen($key) !== 32) {
                throw new RuntimeException('La clé MFA est absente ou invalide.');
            }
            return $key;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
