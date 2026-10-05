<?php

declare(strict_types=1);

namespace App\Security;

use PDO;

/**
 * Limitation du nombre de tentatives par IP (ou clé) sur un endpoint.
 * Utilise la table rate_limits (key_hash, endpoint, count, window_start).
 */
final class RateLimiter
{
    private const ENDPOINT_LOGIN = 'login';

    public function __construct(
        private PDO $db
    ) {}

    /**
     * Vérifie si la requête est autorisée (sous la limite).
     * @param string $keyHash Hash de la clé (ex. hash('sha256', $ip))
     * @param string $endpoint Ex. 'login'
     * @param int $windowSeconds Durée de la fenêtre en secondes (ex. 900 = 15 min)
     * @param int $maxAttempts Nombre max de tentatives dans la fenêtre
     */
    public function isAllowed(string $keyHash, string $endpoint, int $windowSeconds, int $maxAttempts): bool
    {
        try {
            $stmt = $this->db->prepare(
                "SELECT count, window_start FROM rate_limits 
                 WHERE key_hash = :kh AND endpoint = :ep 
                 LIMIT 1"
            );
            $stmt->execute([
                'kh' => $keyHash,
                'ep' => substr($endpoint, 0, 120),
            ]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                return true;
            }
            $windowStart = strtotime($row['window_start']);
            if ($windowStart + $windowSeconds < time()) {
                return true; // fenêtre expirée, on autorise
            }
            return (int) $row['count'] < $maxAttempts;
        } catch (\Throwable $e) {
            return true; // en cas d'erreur BDD, on n'bloque pas l'utilisateur
        }
    }

    /**
     * Enregistre une tentative (échec) pour cette clé/endpoint.
     */
    public function recordAttempt(string $keyHash, string $endpoint, int $windowSeconds): void
    {
        try {
            $endpoint = substr($endpoint, 0, 120);
            $stmt = $this->db->prepare(
                "SELECT id, count, window_start FROM rate_limits 
                 WHERE key_hash = :kh AND endpoint = :ep LIMIT 1"
            );
            $stmt->execute(['kh' => $keyHash, 'ep' => $endpoint]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $now = date('Y-m-d H:i:s');

            if (!$row) {
                $this->db->prepare(
                    "INSERT INTO rate_limits (key_hash, endpoint, count, window_start) 
                     VALUES (:kh, :ep, 1, :ws)"
                )->execute(['kh' => $keyHash, 'ep' => $endpoint, 'ws' => $now]);
                return;
            }

            $windowStart = strtotime($row['window_start']);
            if ($windowStart + $windowSeconds < time()) {
                $this->db->prepare(
                    "UPDATE rate_limits SET count = 1, window_start = :ws 
                     WHERE key_hash = :kh AND endpoint = :ep"
                )->execute(['ws' => $now, 'kh' => $keyHash, 'ep' => $endpoint]);
            } else {
                $this->db->prepare(
                    "UPDATE rate_limits SET count = count + 1 
                     WHERE key_hash = :kh AND endpoint = :ep"
                )->execute(['kh' => $keyHash, 'ep' => $endpoint]);
            }
        } catch (\Throwable $e) {
            // log silencieux ou error_log
        }
    }

    /**
     * Nombre de secondes restantes avant réautorisation (0 si déjà autorisé).
     */
    public function getRemainingSeconds(string $keyHash, string $endpoint, int $windowSeconds): int
    {
        try {
            $stmt = $this->db->prepare(
                "SELECT window_start FROM rate_limits 
                 WHERE key_hash = :kh AND endpoint = :ep LIMIT 1"
            );
            $stmt->execute(['kh' => $keyHash, 'ep' => substr($endpoint, 0, 120)]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                return 0;
            }
            $end = strtotime($row['window_start']) + $windowSeconds;
            $remaining = $end - time();
            return $remaining > 0 ? $remaining : 0;
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /**
     * Constantes pour le login (15 min, 5 tentatives).
     */
    public static function loginWindowSeconds(): int
    {
        return 900; // 15 min
    }

    public static function loginMaxAttempts(): int
    {
        return 5;
    }

    /**
     * Constantes pour l'inscription (24 h, 5 inscriptions max par IP).
     */
    public static function registrationWindowSeconds(): int
    {
        return 86400; // 24h
    }

    public static function registrationMaxAttempts(): int
    {
        return 5;
    }
}
