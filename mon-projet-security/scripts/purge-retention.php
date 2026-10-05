<?php

declare(strict_types=1);

/**
 * Script de purge (rétention) : incidents en base + fichiers de log.
 * À lancer en cron (ex. une fois par semaine) :
 *   0 3 * * 0 cd /path/to/mon-projet-security && php scripts/purge-retention.php
 *
 * Usage : php scripts/purge-retention.php [jours]
 *   jours = nombre de jours de rétention (défaut : 90)
 */

$rootDir = dirname(__DIR__);
require_once $rootDir . '/vendor/autoload.php';

use App\Infrastructure\ApplicationConfig;
use App\Security\IncidentRetention;

ApplicationConfig::initialize($rootDir);

$retentionDays = isset($argv[1]) ? (int) $argv[1] : IncidentRetention::DEFAULT_RETENTION_DAYS;
if ($retentionDays < 1) {
    $retentionDays = IncidentRetention::DEFAULT_RETENTION_DAYS;
}

$logDir = $rootDir . '/var/log';
if (!is_dir($logDir)) {
    $logDir = $rootDir . '/src/App/var/logs';
}

$retention = new IncidentRetention(
    ApplicationConfig::getDatabase(),
    $logDir,
    $retentionDays,
    $retentionDays
);

$result = $retention->purge();

echo sprintf(
    "Rétention %d jours : %d incident(s) supprimé(s), %d fichier(s) de log supprimé(s).\n",
    $retentionDays,
    $result['incidents_deleted'],
    $result['log_files_deleted']
);
