<?php
declare(strict_types=1);

namespace App\Security;

use PDO;
use PDOException;
use App\Infrastructure\ApplicationConfig;

/**
 * Couche d'accès aux données conforme au diagramme d'architecture :
 * - Envoie la « requête sécurisée préparée » à la base
 * - Reçoit les « résultats » de la base
 * - Applique le « filtrage des données sensibles »
 * - Retourne les « données nettoyées » à l'application
 *
 * L'application ne parle plus à la base directement pour le flux login ;
 * tout passe par ce gateway (correspondance 100 % avec le diagramme).
 */
final class SecureDataGateway
{
    public function __construct(
        private PDO $db
    ) {}

    /**
     * Authentification : requête sécurisée → DB → filtrage → données nettoyées.
     * Retourne l'utilisateur sans données sensibles (pas de password_hash) ou null.
     */
    public function authenticateAndGetUser(string $username, string $password): ?array
    {
        $user = $this->executeSecureUserQuery($username);
        if ($user === null) {
            return null;
        }

        $user['login_attempts'] = (int)($user['login_attempts'] ?? 0);
        $user['locked_until'] = $user['locked_until'] ?? null;
        $user['mfa_enabled'] = (int)($user['mfa_enabled'] ?? 0);

        if ($user['locked_until'] && strtotime((string) $user['locked_until']) > time()) {
            return null;
        }

        if (!password_verify($password, (string) ($user['password_hash'] ?? ''))) {
            $this->incrementFailedAttempts((int) $user['id']);
            return null;
        }

        $this->resetFailedAttempts((int) $user['id']);
        $this->updateLastLogin((int) $user['id']);

        return $this->filterSensitiveData($user);
    }

    /**
     * Requête sécurisée préparée vers la base (Middleware → DB).
     */
    private function executeSecureUserQuery(string $username): ?array
    {
        $query = "SELECT id, username, email, password_hash, role,
                         login_attempts, locked_until, mfa_enabled
                  FROM users
                  WHERE username = :username
                  AND deleted_at IS NULL
                  LIMIT 1";

        try {
            $stmt = $this->db->prepare($query);
            $stmt->bindValue(':username', $username, PDO::PARAM_STR);
            $stmt->execute();
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            return $row ?: null;
        } catch (PDOException $e) {
            $fallback = "SELECT id, username, email, password_hash, role
                         FROM users
                         WHERE username = :username
                         LIMIT 1";
            $stmt = $this->db->prepare($fallback);
            $stmt->bindValue(':username', $username, PDO::PARAM_STR);
            $stmt->execute();
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            return $row ?: null;
        }
    }

    /**
     * Filtrage des données sensibles (Résultats → Données nettoyées).
     * Ne retourne que les champs nécessaires à l'application (jamais password_hash).
     */
    private function filterSensitiveData(array $row): array
    {
        $allowed = ['id', 'username', 'email', 'role'];
        $cleaned = [];
        foreach ($allowed as $key) {
            if (array_key_exists($key, $row)) {
                $cleaned[$key] = $row[$key];
            }
        }
        return $cleaned;
    }

    private function incrementFailedAttempts(int $userId): void
    {
        $stmt = $this->db->prepare("
            UPDATE users
            SET login_attempts = login_attempts + 1
            WHERE id = :id
        ");
        $stmt->execute(['id' => $userId]);
    }

    private function resetFailedAttempts(int $userId): void
    {
        $stmt = $this->db->prepare("
            UPDATE users
            SET login_attempts = 0, locked_until = NULL
            WHERE id = :id
        ");
        $stmt->execute(['id' => $userId]);
    }

    private function updateLastLogin(int $userId): void
    {
        $stmt = $this->db->prepare("
            UPDATE users
            SET last_login_at = NOW()
            WHERE id = :id
        ");
        $stmt->execute(['id' => $userId]);
    }
}
