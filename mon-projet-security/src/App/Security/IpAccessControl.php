<?php

declare(strict_types=1);

namespace App\Security;

use PDO;

/**
 * Liste noire / liste blanche d'IP.
 * - Liste noire : IP toujours bloquée.
 * - Liste blanche : si au moins une IP est en whitelist, seules les IP whitelistées sont autorisées.
 */
final class IpAccessControl
{
    public const TYPE_BLACKLIST = 'blacklist';
    public const TYPE_WHITELIST = 'whitelist';

    public function __construct(
        private PDO $db
    ) {}

    /**
     * Retourne true si l'IP doit être bloquée (accès refusé).
     */
    public function isBlocked(string $ip): bool
    {
        $ip = $this->normalizeIp($ip);
        if ($this->isBlacklisted($ip)) {
            return true;
        }
        $whitelistCount = $this->getWhitelistCount();
        if ($whitelistCount > 0 && !$this->isWhitelisted($ip)) {
            return true;
        }
        return false;
    }

    public function isBlacklisted(string $ip): bool
    {
        return $this->hasRule($ip, self::TYPE_BLACKLIST);
    }

    public function isWhitelisted(string $ip): bool
    {
        return $this->hasRule($ip, self::TYPE_WHITELIST);
    }

    /**
     * Nombre d'IP en liste blanche (si > 0, mode whitelist actif).
     */
    public function getWhitelistCount(): int
    {
        try {
            $stmt = $this->db->query("SELECT COUNT(*) FROM ip_access_rules WHERE rule_type = 'whitelist'");
            return (int) $stmt->fetchColumn();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    private function hasRule(string $ip, string $ruleType): bool
    {
        try {
            $stmt = $this->db->prepare(
                "SELECT 1 FROM ip_access_rules WHERE ip_address = :ip AND rule_type = :type LIMIT 1"
            );
            $stmt->execute(['ip' => $this->normalizeIp($ip), 'type' => $ruleType]);
            return (bool) $stmt->fetchColumn();
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Liste toutes les règles (pour l'admin).
     * @return list<array{id: int, ip_address: string, rule_type: string, comment: ?string, created_at: string}>
     */
    public function listRules(): array
    {
        try {
            $stmt = $this->db->query(
                "SELECT id, ip_address, rule_type, comment, created_at FROM ip_access_rules ORDER BY rule_type, ip_address"
            );
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return array_map(fn($r) => [
                'id' => (int) $r['id'],
                'ip_address' => (string) $r['ip_address'],
                'rule_type' => (string) $r['rule_type'],
                'comment' => isset($r['comment']) ? (string) $r['comment'] : null,
                'created_at' => (string) $r['created_at'],
            ], $rows);
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * Ajoute ou met à jour une règle pour une IP (une IP ne peut avoir qu'une règle : blacklist ou whitelist).
     */
    public function addRule(string $ip, string $ruleType, ?string $comment = null): bool
    {
        $ip = $this->normalizeIp($ip);
        if ($ruleType !== self::TYPE_BLACKLIST && $ruleType !== self::TYPE_WHITELIST) {
            return false;
        }
        try {
            $stmt = $this->db->prepare(
                "INSERT INTO ip_access_rules (ip_address, rule_type, comment) VALUES (:ip, :type, :comment)
                 ON DUPLICATE KEY UPDATE rule_type = :type2, comment = :comment2"
            );
            $stmt->execute([
                'ip' => $ip,
                'type' => $ruleType,
                'comment' => $comment ?? '',
                'type2' => $ruleType,
                'comment2' => $comment ?? '',
            ]);
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Supprime la règle pour une IP.
     */
    public function removeRule(string $ip): bool
    {
        try {
            $stmt = $this->db->prepare("DELETE FROM ip_access_rules WHERE ip_address = :ip");
            $stmt->execute(['ip' => $this->normalizeIp($ip)]);
            return $stmt->rowCount() > 0;
        } catch (\Throwable $e) {
            return false;
        }
    }

    private function normalizeIp(string $ip): string
    {
        $ip = trim($ip);
        return $ip === '' ? '0.0.0.0' : $ip;
    }
}
