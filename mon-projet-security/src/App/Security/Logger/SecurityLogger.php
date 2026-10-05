<?php
declare(strict_types=1);

namespace App\Security\Logger;

use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use Psr\Log\LoggerInterface;

/**
 * Logger de sécurité compatible PSR-3 avec rotation, contexte et audit trail
 */
final class SecurityLogger extends AbstractLogger implements SecurityLoggerInterface
{
    private LoggerInterface $logger;
    
    private const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
    private const RETENTION_DAYS = 90;
    
    private string $logDir;
    private array $contextProcessors = [];
    
    public function __construct(LoggerInterface $logger = null, string $logDir = null)
    {
        // Utilise le logger fourni ou utilise cette instance comme logger
        $this->logger = $logger ?? $this;
        
        $this->logDir = $logDir ?? __DIR__ . '/../../var/logs';
        $this->ensureLogDirectory();
        $this->addDefaultProcessors();
    }
    
    public function log($level, $message, array $context = []): void
    {
        // Si on utilise un logger externe, délègue-lui la tâche
        if ($this->logger !== $this) {
            $this->logger->log($level, $message, $context);
            return;
        }
        
        // Sinon, utilise le système de fichier existant
        $context = $this->processContext($context);
        $logEntry = $this->formatLogEntry($level, $message, $context);
        $this->writeToFile($level, $logEntry);
        
        if (in_array($level, [LogLevel::CRITICAL, LogLevel::EMERGENCY, LogLevel::ALERT])) {
            $this->sendAlert($level, $message, $context);
        }
    }
    
    /**
     * Log spécialisé pour les attaques SQLi - version compatible LoggerInterface
     */
    public function logSqlInjection(
        string $ipAddress,
        string $payload,
        int $score,
        array $patterns,
        string $action,
        string $parameter = '',
        string $context = 'unknown'
    ): void {
        $contextArray = [
            'ip' => $ipAddress,
            'value' => $payload,
            'score' => $score,
            'patterns' => $patterns,
            'status' => $action,
            'param' => $parameter,
            'context' => $context,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'referer' => $_SERVER['HTTP_REFERER'] ?? null,
            'timestamp' => microtime(true),
            'payload_hash' => hash('sha256', $payload),
            'payload_preview' => substr($payload, 0, 100),
        ];
        
        // Si on utilise un logger externe, utilise sa méthode warning
        if ($this->logger !== $this) {
            $this->logger->warning('SQL_INJECTION_DETECTED', $contextArray);
            return;
        }
        
        // Sinon, utilise le système existant
        $this->alert('SQL_INJECTION_ATTEMPT', $contextArray);
    }
    
    /**
     * Log pour l'analyse IA
     */
    public function logAiAnalysis(
        string $requestId,
        array $features,
        array $prediction,
        float $processingTime
    ): void {
        $context = [
            'request_id' => $requestId,
            'feature_count' => count($features),
            'prediction_risk' => $prediction['risk'] ?? 0,
            'prediction_confidence' => $prediction['confidence'] ?? 0,
            'processing_time_ms' => $processingTime * 1000,
            'model_version' => '2026.1.0'
        ];
        
        if ($this->logger !== $this) {
            $this->logger->info('IA_ANALYSIS_COMPLETED', $context);
            return;
        }
        
        $this->info('IA_ANALYSIS_COMPLETED', $context);
    }
    
    /**
     * Statistiques avancées
     */
    public function getStatistics(int $days = 30): array
    {
        $stats = [
            'total_attacks' => 0,
            'blocked_attacks' => 0,
            'by_type' => [],
            'by_ip' => [],
            'timeline' => [],
            'success_rate' => 0.0
        ];
        
        $files = glob($this->logDir . '/security_*.log');
        $cutoff = time() - ($days * 86400);
        
        foreach ($files as $file) {
            if (filemtime($file) < $cutoff) continue;
            
            $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            
            foreach ($lines as $line) {
                $data = json_decode($line, true);
                if (is_array($data)) {
                    // Format JSON structuré
                    $msg = $data['message'] ?? '';
                    if (!str_contains($msg, 'SQL_INJECTION') && !str_contains($msg, 'SQL_INJECTION_ATTEMPT')) {
                        continue;
                    }
                    $stats['total_attacks']++;
                    if (isset($data['status']) && stripos((string) $data['status'], 'BLOCKED') !== false) {
                        $stats['blocked_attacks']++;
                    }
                    $ip = $data['ip'] ?? null;
                    if ($ip) {
                        $stats['by_ip'][$ip] = ($stats['by_ip'][$ip] ?? 0) + 1;
                    }
                    $type = $data['context'] ?? $data['status'] ?? 'unknown';
                    $stats['by_type'][$type] = ($stats['by_type'][$type] ?? 0) + 1;
                    continue;
                }
                // Ancien format texte (rétrocompatibilité)
                if (str_contains($line, 'SQL_INJECTION')) {
                    $stats['total_attacks']++;
                    if (str_contains($line, 'BLOCKED')) {
                        $stats['blocked_attacks']++;
                    }
                    if (preg_match('/IP: ([\d\.:a-fA-F]+)/', $line, $matches)) {
                        $ip = $matches[1];
                        $stats['by_ip'][$ip] = ($stats['by_ip'][$ip] ?? 0) + 1;
                    }
                    if (preg_match('/Type: (\w+)/', $line, $matches)) {
                        $type = $matches[1];
                        $stats['by_type'][$type] = ($stats['by_type'][$type] ?? 0) + 1;
                    }
                }
            }
        }
        
        if ($stats['total_attacks'] > 0) {
            $stats['success_rate'] = round(
                ($stats['blocked_attacks'] / $stats['total_attacks']) * 100, 2
            );
        }
        
        // Tri par nombre d'attaques
        arsort($stats['by_ip']);
        arsort($stats['by_type']);
        
        return $stats;
    }
    
    /**
     * Format structuré : une ligne = un objet JSON (JSON Lines / ndjson).
     * Facilite l'ingestion par des outils (ELK, Splunk, etc.).
     */
    private function formatLogEntry(string $level, string $message, array $context): string
    {
        $requestId = $context['request_id'] ?? bin2hex(random_bytes(8));
        $payload = [
            '@timestamp' => date('Y-m-d\TH:i:s.uP'),
            'level' => strtoupper($level),
            'message' => $message,
            'request_id' => $requestId,
        ];
        foreach ($context as $key => $value) {
            if ($key !== 'request_id') {
                $payload[$key] = $value;
            }
        }
        return json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    }
    
    private function ensureLogDirectory(): void
    {
        if (!is_dir($this->logDir)) {
            mkdir($this->logDir, 0755, true);
            chmod($this->logDir, 0755);
        }
        
        // Créer les fichiers de log s'ils n'existent pas
        $files = [
            'security' => 'security_{date}.log',
            'access' => 'access_{date}.log',
            'ai' => 'ai_analysis_{date}.log',
            'error' => 'errors_{date}.log'
        ];
        
        foreach ($files as $type => $pattern) {
            $filename = str_replace('{date}', date('Y-m-d'), $pattern);
            $filepath = $this->logDir . '/' . $filename;
            
            if (!file_exists($filepath)) {
                touch($filepath);
                chmod($filepath, 0644);
            }
        }
    }
    
    private function writeToFile(string $level, string $entry): void
    {
        $file = $this->logDir . '/security_' . date('Y-m-d') . '.log';
        file_put_contents($file, $entry, FILE_APPEND | LOCK_EX);
    }

    private function sendAlert(string $level, string $message, array $context): void
    {
        // Hook futur : email, Slack, webhook SOC
    }

    private function processContext(array $context): array
    {
        return array_merge([
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'uri' => $_SERVER['REQUEST_URI'] ?? 'cli',
        ], $context);
    }

    private function addDefaultProcessors(): void
    {
        $this->contextProcessors[] = fn(array $ctx) => $ctx;
    }
        /**
     * Méthode de log générique (PSR-3 compatible)
     * @param string $level Niveau de log (ERROR, WARNING, INFO, etc.)
     * @param string $message Message à logger
     * @param array $context Contexte supplémentaire
     */

    /**
     * Méthode de compatibilité pour logError()
     */
    public function logError(string $message, array $context = []): void
    {
        $this->log('ERROR', $message, $context);
    }
}