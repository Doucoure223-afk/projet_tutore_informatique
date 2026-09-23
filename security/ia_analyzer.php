<?php
/**
 * Simulateur d'IA pour le diagramme de séquence
 * Correspond exactement à "POST /analyse {sql: "...", context: "login"}"
 * et "Features extraction + ML"
 */
class AIAnalyzer {
    private $mockResponses = [
        "' OR '1'='1" => ['risk' => 0.92, 'confidence' => 0.85, 'type' => 'TAUTOLOGY'],
        "' UNION SELECT" => ['risk' => 0.95, 'confidence' => 0.88, 'type' => 'UNION_SQLi'],
        "' OR SLEEP" => ['risk' => 0.87, 'confidence' => 0.82, 'type' => 'TIME_BASED'],
        "admin' --" => ['risk' => 0.75, 'confidence' => 0.78, 'type' => 'COMMENT_INJECTION'],
        "'; DROP TABLE" => ['risk' => 0.98, 'confidence' => 0.91, 'type' => 'DESTRUCTIVE'],
        "' OR '1'='1' --" => ['risk' => 0.90, 'confidence' => 0.87, 'type' => 'TAUTOLOGY_WITH_COMMENT'],
        "' AND 1=1 --" => ['risk' => 0.82, 'confidence' => 0.80, 'type' => 'BOOLEAN'],
        "' UNION ALL SELECT" => ['risk' => 0.96, 'confidence' => 0.89, 'type' => 'UNION_ALL']
    ];
    
    private $contextFactors = [
        'login' => 1.2,    // Login plus sensible
        'search' => 1.0,   // Recherche moyenne
        'register' => 1.1, // Inscription
        'admin' => 1.3     // Zone admin très sensible
    ];
    
    /**
     * Analyse par IA comme dans le diagramme
     * Correspond à: POST /analyse {sql: "SELECT...", context: "login"}
     */
    public function analyze($sqlQuery, $context = 'unknown') {
        $timestamp = date('Y-m-d H:i:s');
        $contextFactor = $this->contextFactors[$context] ?? 1.0;
        
        // Simulation d'extraction de features et ML
        $features = $this->extractFeatures($sqlQuery);
        
        // Simulation de prédiction IA
        $risk = $this->predictRisk($sqlQuery, $features, $contextFactor);
        $confidence = $this->calculateConfidence($features);
        $type = $this->classifyAttack($sqlQuery);
        
        // Décision basée sur le risque
        $decision = $risk > 0.7 ? 'BLOCK' : 'ALLOW';
        
        $result = [
            'risk' => $risk,
            'confidence' => $confidence,
            'type' => $type,
            'features' => $features,
            'context' => $context,
            'context_factor' => $contextFactor,
            'timestamp' => $timestamp,
            'decision' => $decision,
            'analysis_method' => 'MOCK_IA_SIMULATION',
            'query_hash' => md5($sqlQuery)
        ];
        
        // Log pour démonstration
        error_log("IA Analysis - Context: $context - Risk: $risk - Decision: $decision");
        
        return $result;
    }
    
    /**
     * Features extraction + ML (comme dans le diagramme)
     */
    private function extractFeatures($sqlQuery) {
        $query = strtolower($sqlQuery);
        
        $features = [
            'length' => strlen($sqlQuery),
            'word_count' => str_word_count($sqlQuery),
            'special_chars' => preg_match_all('/[\'"=;#()\-]/', $sqlQuery),
            'has_union' => (int)(strpos($query, 'union') !== false),
            'has_select' => (int)(strpos($query, 'select') !== false),
            'has_insert' => (int)(strpos($query, 'insert') !== false),
            'has_delete' => (int)(strpos($query, 'delete') !== false),
            'has_drop' => (int)(strpos($query, 'drop') !== false),
            'has_comment' => (int)(preg_match('/--|#|\/\*/', $query)),
            'has_sleep' => (int)(strpos($query, 'sleep') !== false),
            'has_benchmark' => (int)(strpos($query, 'benchmark') !== false),
            'has_or' => (int)(strpos($query, ' or ') !== false),
            'has_and' => (int)(strpos($query, ' and ') !== false),
            'has_equal' => (int)(strpos($query, '=') !== false),
            'has_semicolon' => (int)(strpos($query, ';') !== false),
            'has_single_quote' => (int)(strpos($query, "'") !== false),
            'has_double_quote' => (int)(strpos($query, '"') !== false),
            'keyword_count' => $this->countKeywords($sqlQuery),
            'entropy' => $this->calculateEntropy($sqlQuery)
        ];
        
        return $features;
    }
    
    private function predictRisk($sqlQuery, $features, $contextFactor) {
        // Vérifier d'abord les réponses mockées
        foreach ($this->mockResponses as $pattern => $response) {
            if (strpos(strtolower($sqlQuery), strtolower($pattern)) !== false) {
                $adjustedRisk = min($response['risk'] * $contextFactor, 1.0);
                return round($adjustedRisk, 2);
            }
        }
        
        // Calcul de risque basé sur les features
        $risk = 0.1; // Base
        
        // Facteurs augmentant le risque
        if ($features['has_union']) $risk += 0.25;
        if ($features['has_select']) $risk += 0.15;
        if ($features['has_comment']) $risk += 0.20;
        if ($features['has_drop'] || $features['has_delete']) $risk += 0.30;
        if ($features['has_sleep'] || $features['has_benchmark']) $risk += 0.25;
        
        // Caractères spéciaux
        if ($features['special_chars'] > 5) $risk += 0.20;
        if ($features['special_chars'] > 10) $risk += 0.15;
        
        // Longueur suspecte
        if ($features['length'] > 200) $risk += 0.10;
        
        // Entropy élevée
        if ($features['entropy'] > 4.0) $risk += 0.15;
        
        // Appliquer le facteur de contexte
        $risk *= $contextFactor;
        
        return min(round($risk, 2), 1.0);
    }
    
    private function calculateConfidence($features) {
        $confidence = 0.5; // Base
        
        // Facteurs augmentant la confiance
        $totalIndicators = 0;
        $positiveIndicators = 0;
        
        $indicators = ['has_union', 'has_select', 'has_comment', 'has_drop', 'has_delete', 'has_sleep'];
        
        foreach ($indicators as $indicator) {
            if ($features[$indicator] > 0) {
                $positiveIndicators++;
            }
            $totalIndicators++;
        }
        
        if ($totalIndicators > 0) {
            $confidence += ($positiveIndicators / $totalIndicators) * 0.3;
        }
        
        // Caractères spéciaux
        if ($features['special_chars'] > 3) {
            $confidence += 0.15;
        }
        
        // Mots-clés multiples
        if ($features['keyword_count'] > 2) {
            $confidence += 0.10;
        }
        
        return min(round($confidence, 2), 0.95);
    }
    
    private function classifyAttack($sqlQuery) {
        $query = strtolower($sqlQuery);
        
        if (strpos($query, 'union') !== false && strpos($query, 'select') !== false) {
            return 'UNION_BASED';
        } elseif (strpos($query, 'sleep') !== false || strpos($query, 'benchmark') !== false) {
            return 'TIME_BASED';
        } elseif (strpos($query, 'extractvalue') !== false || strpos($query, 'updatexml') !== false) {
            return 'ERROR_BASED';
        } elseif (strpos($query, 'drop') !== false || strpos($query, 'delete') !== false) {
            return 'DESTRUCTIVE';
        } elseif (preg_match('/--|#|\/\*/', $query)) {
            return 'COMMENT_INJECTION';
        } elseif (strpos($query, 'or') !== false && strpos($query, '=') !== false) {
            return 'TAUTOLOGY';
        } elseif (strpos($query, 'and') !== false && strpos($query, '=') !== false) {
            return 'BOOLEAN';
        } else {
            return 'SUSPICIOUS';
        }
    }
    
    private function countKeywords($sqlQuery) {
        $keywords = ['select', 'union', 'insert', 'delete', 'drop', 'update', 'create', 'alter', 'from', 'where', 'and', 'or'];
        $count = 0;
        $query = strtolower($sqlQuery);
        
        foreach ($keywords as $keyword) {
            if (preg_match('/\b' . preg_quote($keyword, '/') . '\b/', $query)) {
                $count++;
            }
        }
        
        return $count;
    }
    
    private function calculateEntropy($string) {
        if (empty($string)) return 0;
        
        $entropy = 0;
        $len = strlen($string);
        $charCounts = [];
        
        // Compter les occurrences de chaque caractère
        for ($i = 0; $i < $len; $i++) {
            $char = $string[$i];
            $charCounts[$char] = ($charCounts[$char] ?? 0) + 1;
        }
        
        // Calculer l'entropie
        foreach ($charCounts as $count) {
            $probability = $count / $len;
            $entropy -= $probability * log($probability, 2);
        }
        
        return round($entropy, 2);
    }
    
    /**
     * Décision finale basée sur le risque IA
     * Risque > 0.7 -> Blocage (comme dans le diagramme)
     */
    public function shouldBlock($iaResult) {
        return $iaResult['risk'] > 0.7;
    }
    
    /**
     * Méthode pour les tests
     */
    public function testAnalysis($queries = []) {
        $results = [];
        
        $testQueries = empty($queries) ? array_keys($this->mockResponses) : $queries;
        
        foreach ($testQueries as $query) {
            $results[$query] = $this->analyze($query, 'test');
        }
        
        return $results;
    }
}
?>