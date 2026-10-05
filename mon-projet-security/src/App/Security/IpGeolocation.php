<?php

declare(strict_types=1);

namespace App\Security;

use PDO;

/**
 * Géolocalisation des IP via ip-api.com (gratuit, sans clé).
 * Résultats mis en cache en base pour limiter les appels (45 req/min en gratuit).
 */
final class IpGeolocation
{
    private const API_URL = 'http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city';
    private const CACHE_TTL_DAYS = 30;
    private const LOCAL_IPS = ['127.0.0.1', '::1', '0.0.0.0'];

    public function __construct(
        private PDO $db
    ) {}

    /**
     * Retourne un libellé court pour l'affichage : "Ville, Pays" ou "Pays" ou "Réseau local".
     */
    public function getLocationLabel(string $ip): string
    {
        $data = $this->resolve($ip);
        if ($data['country_name'] === '') {
            return 'Réseau local';
        }
        if ($data['city'] !== '' && $data['city'] !== null) {
            return $data['city'] . ', ' . $data['country_name'];
        }
        return $data['country_name'];
    }

    /**
     * Résout une IP : country_code, country_name, region, city (depuis cache ou API).
     * @return array{country_code: string, country_name: string, region: ?string, city: ?string}
     */
    public function resolve(string $ip): array
    {
        $ip = trim($ip);
        if ($ip === '' || in_array($ip, self::LOCAL_IPS, true)) {
            return ['country_code' => 'XX', 'country_name' => '', 'region' => null, 'city' => null];
        }

        $cached = $this->getFromCache($ip);
        if ($cached !== null) {
            return $cached;
        }

        $data = $this->fetchFromApi($ip);
        if ($data !== null) {
            $this->saveToCache($ip, $data);
            return $data;
        }

        return ['country_code' => 'XX', 'country_name' => '', 'region' => null, 'city' => null];
    }

    private function getFromCache(string $ip): ?array
    {
        try {
            $stmt = $this->db->prepare(
                'SELECT country_code, country_name, region, city FROM ip_geo_cache 
                 WHERE ip_address = :ip AND updated_at >= DATE_SUB(NOW(), INTERVAL ' . self::CACHE_TTL_DAYS . ' DAY) LIMIT 1'
            );
            $stmt->execute(['ip' => $ip]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                return null;
            }
            return [
                'country_code' => (string) $row['country_code'],
                'country_name' => (string) $row['country_name'],
                'region' => isset($row['region']) && $row['region'] !== '' ? (string) $row['region'] : null,
                'city' => isset($row['city']) && $row['city'] !== '' ? (string) $row['city'] : null,
            ];
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function fetchFromApi(string $ip): ?array
    {
        $url = sprintf(self::API_URL, urlencode($ip));
        $ctx = stream_context_create([
            'http' => [
                'timeout' => 3,
                'ignore_errors' => true,
            ],
        ]);
        $json = @file_get_contents($url, false, $ctx);
        if ($json === false) {
            return null;
        }
        $data = json_decode($json, true);
        if (!is_array($data) || ($data['status'] ?? '') !== 'success') {
            return null;
        }
        return [
            'country_code' => (string) ($data['countryCode'] ?? 'XX'),
            'country_name' => (string) ($data['country'] ?? ''),
            'region' => isset($data['regionName']) && $data['regionName'] !== '' ? (string) $data['regionName'] : null,
            'city' => isset($data['city']) && $data['city'] !== '' ? (string) $data['city'] : null,
        ];
    }

    private function saveToCache(string $ip, array $data): void
    {
        try {
            $stmt = $this->db->prepare(
                "INSERT INTO ip_geo_cache (ip_address, country_code, country_name, region, city) 
                 VALUES (:ip, :cc, :cn, :region, :city) 
                 ON DUPLICATE KEY UPDATE country_code = VALUES(country_code), country_name = VALUES(country_name), 
                 region = VALUES(region), city = VALUES(city), updated_at = NOW()"
            );
            $stmt->execute([
                'ip' => $ip,
                'cc' => $data['country_code'] ?? 'XX',
                'cn' => $data['country_name'] ?? '',
                'region' => $data['region'] ?? null,
                'city' => $data['city'] ?? null,
            ]);
        } catch (\Throwable $e) {
            // ignore
        }
    }
}
