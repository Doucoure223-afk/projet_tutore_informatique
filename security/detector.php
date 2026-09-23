<?php
class SQLInjectionDetector {
    private $patterns = [
        // Patterns critiques (score 100)
        "/' OR '1'='1/i" => 100,
        "/' OR '1'='1' --/i" => 100,
        "/' OR 1=1 --/i" => 100,
        "/' UNION.*SELECT/i" => 100,
        "/' UNION ALL SELECT/i" => 100,
        "/'; DROP TABLE/i" => 100,
        "/'; DELETE FROM/i" => 100,
        "/SLEEP\(/i" => 100,
        "/BENCHMARK\(/i" => 100,
        "/LOAD_FILE\(/i" => 100,
        
        // Patterns moyens (score 50)
        "/--|#|\/\*/" => 50,
        "/INSERT INTO/i" => 50,
        "/UPDATE.*SET/i" => 50,
        
        // Patterns faibles (score 20)
        "/SELECT.*FROM/i" => 20,
        "/WHERE.*=/i" => 20,
        "/AND|OR/i" => 20,
        // AJOUTER ces patterns manquants :
        "/' AND '1'='1/i" => 100,
        "/' AND '1'='1' --/i" => 100,
        "/' AND 1=1 --/i" => 100,
        "/' OR '1'='1--/i" => 100,
        "/' AND '1'='1--/i" => 100,
        
        // Pour détecter les commentaires SQL mieux
        "/--[\s\S]*$/i" => 30,
        "/#[\s\S]*$/i" => 30,
        "/\/\*[\s\S]*\*\//i" => 30,
        // Patterns ajoutés (lignes 28-38) ✅
    ];
    
    private $blockMode = true;
    private $logger;
    
    public function __construct($logger = null) {
        $this->logger = $logger;
    }
    
    /**
     * Analyse avec score comme dans le diagramme de séquence
     */
    public function analyzeWithScore($input, $paramName = '', $context = '') {
        if (empty($input) || !is_string($input)) {
            return [
                'block' => false, 
                'score' => 0, 
                'patterns' => [], 
                'needs_ai' => false,
                'message' => 'Input vide ou non-string'
            ];
        }
        
        $input = urldecode($input);
        $score = 0;
        $detectedPatterns = [];
        
        // 1. Pattern matching immédiat (comme dans le diagramme)
        foreach ($this->patterns as $pattern => $patternScore) {
            if (preg_match($pattern, $input)) {
                $score += $patternScore;
                $detectedPatterns[] = $pattern;
            }
        }
        
        // 2. Détection des caractères spéciaux
        $specialChars = preg_match_all('/[\'"=;#()\-]/', $input);
        if ($specialChars > 3) {
            $score += $specialChars * 15;
        }
        
        // 3. Longueur anormale
        if (strlen($input) > 500) {
            $score += 30;
        }
        
        // 4. Décision comme dans le diagramme de séquence
        $result = [
            'block' => false,
            'score' => $score,
            'patterns' => $detectedPatterns,
            'needs_ai' => false,
            'input_preview' => substr($input, 0, 100)
        ];
        
        if ($score >= 80) {
            // Règle détectée (score > 80) -> Blocage immédiat
            $result['block'] = true;
            $result['decision'] = 'IMMEDIATE_BLOCK';
            
            if ($this->logger) {
                $this->logger->logAttack(
                    $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                    'SQL_INJECTION_HIGH_SCORE',
                    $input,
                    $paramName,
                    $score,
                    $detectedPatterns,
                    'BLOCKED'
                );
            }
        } elseif ($score >= 30 && $score < 80) {
            // Analyse IA nécessaire (score entre 30 et 80)
            $result['needs_ai'] = true;
            $result['decision'] = 'NEEDS_AI_ANALYSIS';
            
            if ($this->logger) {
                $this->logger->logAttack(
                    $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                    'SQL_INJECTION_SUSPICIOUS',
                    $input,
                    $paramName,
                    $score,
                    $detectedPatterns,
                    'PENDING_IA'
                );
            }
        } else {
            // Risque faible -> Pas de blocage
            $result['decision'] = 'LOW_RISK_ALLOWED';
        }
        
        return $result;
    }
    
    /**
     * Version simple pour compatibilité
     */
    public function detect($input, $paramName = '') {
        $analysis = $this->analyzeWithScore($input, $paramName);
        return $analysis['block'];
    }
    
    public function sanitizeInput($input) {
        if (is_array($input)) {
            $result = [];
            foreach ($input as $key => $value) {
                $result[$key] = $this->sanitizeInput($value);
            }
            return $result;
        }
        
        if (!is_string($input)) {
            return $input;
        }
        
        // Supprime les balises
        $input = strip_tags($input);
        
        // Échappe les caractères spéciaux HTML
        $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
        
        // Supprime les espaces multiples
        $input = preg_replace('/\s+/', ' ', $input);
        
        return trim($input);
    }
    
    public function setBlockMode($mode) {
        $this->blockMode = (bool)$mode;
    }
    
    public function getBlockMode() {
        return $this->blockMode;
    }
    
    public function escapeSql($input, $connection = null) {
        if ($connection && $connection instanceof mysqli) {
            return $connection->real_escape_string($input);
        }
        return addslashes($input);
    }
    
    /**
     * Méthode utilitaire pour les tests
     */
    public function getPatterns() {
        return array_keys($this->patterns);
    }
}
?>