<?php
class SecurityLogger {
    private $logFile;
    private $accessFile;
    private $iaLogFile;
    private $errorLogFile;
    
    public function __construct($logFile = null) {
        $logDir = __DIR__ . '/../logs';
        
        // Crée le dossier logs s'il n'existe pas
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        
        $this->logFile = $logFile ?: $logDir . '/attaques.log';
        $this->accessFile = $logDir . '/access.log';
        $this->iaLogFile = $logDir . '/ia_analysis.log';
        $this->errorLogFile = $logDir . '/errors.log';
        
        // Initialise les fichiers s'ils n'existent pas
        $this->initializeLogFiles();
    }
    
    private function initializeLogFiles() {
        $files = [
            $this->logFile,
            $this->accessFile,
            $this->iaLogFile,
            $this->errorLogFile
        ];
        
        foreach ($files as $file) {
            if (!file_exists($file)) {
                file_put_contents($file, "=== LOG FILE CREATED: " . date('Y-m-d H:i:s') . " ===\n\n");
            }
        }
    }
    
    public function logAttack($ip, $attackType, $payload, $parameter = '', $score = 0, $patterns = [], $action = '') {
        $timestamp = date('Y-m-d H:i:s');
        $payload = substr($payload, 0, 200);
        $patternsStr = !empty($patterns) ? implode(', ', array_slice($patterns, 0, 3)) : 'none';
        

    $logEntry = sprintf(
        "[%s] ATTACK - IP: %s | Type: %s | Param: %s | Score: %d | Patterns: %s | Action: %s | Payload: %s\n",
        $timestamp,
        $ip,
        $attackType,
        $parameter,
        $score,
        $patternsStr,
        $action,      // "BLOCKED" ou "PENDING_IA"
        $payload      // Le payload réel
    );
        
        file_put_contents($this->logFile, $logEntry, FILE_APPEND | LOCK_EX);
        
        // Log système pour debug
        error_log("SECURITY: $attackType - IP: $ip - Score: $score - Action: $action");
        
        return true;
    }
    
    /**
     * Log spécifique pour analyse IA (comme dans le diagramme)
     */
    public function logIAnalysis($ip, $sqlQuery, $iaResult, $context = '') {
        $timestamp = date('Y-m-d H:i:s');
        
        $logEntry = sprintf(
            "[%s] IA_ANALYSIS - IP: %s | Context: %s | Risk: %.2f | Confidence: %.2f | Type: %s | Decision: %s | Query: %s\n",
            $timestamp,
            $ip,
            $context,
            $iaResult['risk'] ?? 0,
            $iaResult['confidence'] ?? 0,
            $iaResult['type'] ?? 'UNKNOWN',
            $iaResult['decision'] ?? 'UNKNOWN',
            substr($sqlQuery, 0, 150)
        );
        
        file_put_contents($this->iaLogFile, $logEntry, FILE_APPEND | LOCK_EX);
        
        // Si risque élevé, log aussi dans le fichier principal
        if (($iaResult['risk'] ?? 0) > 0.7) {
            $this->logAttack(
                $ip,
                'SQL_INJECTION_IA_CONFIRMED',
                $sqlQuery,
                $context,
                intval($iaResult['risk'] * 100),
                [],
                'BLOCKED_BY_IA'
            );
        }
        
        return true;
    }
    
    public function logAccess($username, $action, $status) {
        $timestamp = date('Y-m-d H:i:s');
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        $logEntry = sprintf(
            "[%s] ACCESS - IP: %s | User: %s | Action: %s | Status: %s\n",
            $timestamp,
            $ip,
            $username,
            $action,
            $status
        );
        
        file_put_contents($this->accessFile, $logEntry, FILE_APPEND | LOCK_EX);
        
        return true;
    }
    
    public function logError($message, $level = 'ERROR') {
        $timestamp = date('Y-m-d H:i:s');
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        $logEntry = sprintf(
            "[%s] %s - IP: %s | Message: %s\n",
            $timestamp,
            $level,
            $ip,
            $message
        );
        
        file_put_contents($this->errorLogFile, $logEntry, FILE_APPEND | LOCK_EX);
        
        return true;
    }
    
    // Getters pour les fichiers
    public function getLogFile() {
        return $this->logFile;
    }
    
    public function getLogContent() {
        if (!file_exists($this->logFile)) {
            return '';
        }
        return file_get_contents($this->logFile);
    }
    
    public function getIALogContent() {
        if (!file_exists($this->iaLogFile)) {
            return '';
        }
        return file_get_contents($this->iaLogFile);
    }
    
    public function getRecentAttacks($limit = 10) {
        if (!file_exists($this->logFile)) {
            return [];
        }
        
        $lines = file($this->logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $lines = array_reverse($lines);
        $lines = array_slice($lines, 0, $limit);
        
        return $lines;
    }
    
    /**
     * Récupérer les logs IA
     */
    public function getIALogs($limit = 10) {
        if (!file_exists($this->iaLogFile)) {
            return [];
        }
        
        $lines = file($this->iaLogFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $lines = array_reverse($lines);
        $lines = array_slice($lines, 0, $limit);
        
        return $lines;
    }
    
    /**
     * Statistiques des attaques
     */
    public function getStats($days = 7) {
        if (!file_exists($this->logFile)) {
            return ['total' => 0, 'blocked' => 0, 'by_type' => []];
        }
        
        $stats = ['total' => 0, 'blocked' => 0, 'by_type' => []];
        $lines = file($this->logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $cutoffDate = date('Y-m-d', strtotime("-$days days"));
        
        foreach ($lines as $line) {
            if (preg_match('/\[(\d{4}-\d{2}-\d{2})/', $line, $matches)) {
                $logDate = $matches[1];
                
                if ($logDate >= $cutoffDate) {
                    $stats['total']++;
                    
                    // Compter les blocages
                    if (strpos($line, 'BLOCKED') !== false || strpos($line, 'Action: BLOCKED') !== false) {
                        $stats['blocked']++;
                    }
                    
                    // Analyser le type
                    if (preg_match('/Type: (\w+)/', $line, $typeMatches)) {
                        $type = $typeMatches[1];
                        $stats['by_type'][$type] = ($stats['by_type'][$type] ?? 0) + 1;
                    }
                }
            }
        }
        
        return $stats;
    }
}
?>