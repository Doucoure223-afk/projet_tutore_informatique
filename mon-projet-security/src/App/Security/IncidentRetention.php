<?php

declare(strict_types=1);

namespace App\Security;

use PDO;

/**
 * Politique de rétention : purge des incidents et des fichiers de log obsolètes.
 * À exécuter périodiquement (cron) pour respecter la rétention configurée.
 */
final class IncidentRetention
{
    /** Nombre de jours de conservation par défaut (incidents en base et logs). */
    public const DEFAULT_RETENTION_DAYS = 90;

    public function __construct(
        private PDO $db,
        private string $logDir,
        private int $incidentRetentionDays = self::DEFAULT_RETENTION_DAYS,
        private int $logRetentionDays = self::DEFAULT_RETENTION_DAYS
    ) {
    }

    /**
     * Supprime les incidents plus anciens que la rétention configurée.
     * @return int Nombre de lignes supprimées
     */
    public function purgeIncidents(): int
    {
        try {
            $stmt = $this->db->prepare(
                'DELETE FROM security_incidents WHERE created_at < DATE_SUB(NOW(), INTERVAL :days DAY)'
            );
            $stmt->bindValue('days', $this->incidentRetentionDays, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->rowCount();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /**
     * Supprime les fichiers de log (security_*.log, etc.) plus anciens que la rétention configurée.
     * @return int Nombre de fichiers supprimés
     */
    public function purgeLogFiles(): int
    {
        $cutoff = time() - ($this->logRetentionDays * 86400);
        $count = 0;
        $patterns = ['security_*.log', 'access_*.log', 'ai_analysis_*.log', 'errors_*.log'];

        foreach ($patterns as $pattern) {
            $files = glob($this->logDir . '/' . $pattern) ?: [];
            foreach ($files as $path) {
                if (is_file($path) && filemtime($path) < $cutoff) {
                    if (@unlink($path)) {
                        $count++;
                    }
                }
            }
        }

        return $count;
    }

    /**
     * Exécute la purge complète (incidents + logs).
     * @return array{incidents_deleted: int, log_files_deleted: int}
     */
    public function purge(): array
    {
        return [
            'incidents_deleted' => $this->purgeIncidents(),
            'log_files_deleted' => $this->purgeLogFiles(),
        ];
    }
}
