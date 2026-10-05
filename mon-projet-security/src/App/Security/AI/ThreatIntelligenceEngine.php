<?php

declare(strict_types=1);

namespace App\Security\AI;

/**
 * Classe de résultat d'analyse de menace
 */
final class ThreatAnalysisResult
{
    public function __construct(
        public float $riskScore,
        public float $confidence,
        public string $threatType,
        public array $features,
        public string $modelVersion,
        public float $processingTime,
        public array $recommendations,
        public array $metadata
    ) {}
}

/**
 * Moteur d'Intelligence des Menaces pour SQL Injection
 * Version finale unifiée - Compatible avec login.php
 */
final class ThreatIntelligenceEngine
{
    private const RISK_THRESHOLD = 0.75;
    private const MODEL_VERSION = '2026.1.0';
    
    private array $threatPatterns = [
        // Injection SQL classique
        '/\' (?:OR|AND) \'1\'=\'1/i' => 0.95,
        '/\' (?:OR|AND) 1=1/i' => 0.92,
        '/\' UNION[\s\W]*SELECT/i' => 0.96,
        '/\' UNION ALL SELECT/i' => 0.97,
        
        // Injection basée sur le temps
        '/SLEEP\(/i' => 0.88,
        '/BENCHMARK\(/i' => 0.87,
        '/WAITFOR DELAY/i' => 0.89,
        
        // Injection destructive
        '/\'?; (?:DROP|DELETE|TRUNCATE|UPDATE|INSERT)/i' => 0.98,
        
        // Injection par commentaire
        '/--[\s\S]*$/i' => 0.75,
        '/#[\s\S]*$/i' => 0.72,
        '/\/\*[\s\S]*\*\//i' => 0.78,
        
        // Injection booléenne aveugle
        '/\' (?:AND|OR) \d+=\d+/i' => 0.82,
        '/\' (?:AND|OR) \'[^\']+\'=\'[^\']+\'/i' => 0.80,
        
        // Évasion d'encodage
        '/%27|%20OR%20|%20AND%20/i' => 0.85,
        '/\b(?:CHAR|ASCII|HEX|UNHEX)\(/i' => 0.70,
    ];
    
    private array $contextWeights = [
        'login' => 1.3,
        'registration' => 1.2,
        'search' => 1.1,
        'admin_panel' => 1.4,
        'api' => 1.25,
        'file_upload' => 1.35,
        'default' => 1.0
    ];
    
    private array $behavioralPatterns = [];
    private float $confidence = 0.0;
    private string $requestId;
    private array $mlModels = [];
    private bool $useRealML;
    
    public function __construct(bool $useRealML = false)
    {
        $this->requestId = bin2hex(random_bytes(8));
        $this->useRealML = $useRealML;
        $this->loadModels();
        $this->loadBehavioralPatterns();
    }
    
    /**
     * MÉTHODE DEMANDÉE PAR login.php - CORRIGÉE
     * @param string $input Entrée à analyser
     * @param array $context Contexte de la requête
     * @param string|null $sessionId ID de session (optionnel)
     * @return ThreatAnalysisResult Résultat de l'analyse
     */
    public function analyzeThreat(string $input, array $context, ?string $sessionId = null): ThreatAnalysisResult
    {
        $startTime = microtime(true);
        
        // Utiliser l'analyse standard
        $contextType = $context['type'] ?? 'default';
        $analysis = $this->analyze($input, $contextType);
        
        // Ajouter l'analyse de session si disponible
        $sessionAnalysis = null;
        if ($sessionId !== null) {
            $sessionAnalysis = $this->analyzeSession($sessionId);
        }
        
        $processingTime = microtime(true) - $startTime;
        
        // Retourner le résultat dans le format attendu
        return new ThreatAnalysisResult(
            riskScore: $analysis['risk'],
            confidence: $analysis['confidence'],
            threatType: $analysis['type'],
            features: $analysis['features'],
            modelVersion: self::MODEL_VERSION,
            processingTime: $processingTime,
            recommendations: $analysis['recommendations'] ?? $this->generateRecommendations($analysis['risk'], $context),
            metadata: [
                'ml_used' => $this->useRealML,
                'behavior_analyzed' => $sessionId !== null,
                'feature_count' => count($analysis['features']),
                'request_id' => $this->requestId,
                'session_analysis' => $sessionAnalysis
            ]
        );
    }
    
    /**
     * Analyse une entrée pour détecter les menaces SQLi (Méthode principale)
     */
    public function analyze(string $input, string $context = 'unknown'): array
    {
        $startTime = microtime(true);
        
        // Normalisation de l'entrée
        $normalizedInput = $this->normalizeInput($input);
        
        // Extraction des caractéristiques
        $features = $this->extractFeatures($normalizedInput);
        
        // Détection de patterns
        $patternMatches = $this->detectPatterns($normalizedInput);
        
        // Calcul du risque
        $baseRisk = $this->calculateBaseRisk($patternMatches, $features);
        
        // Application du contexte
        $contextWeight = $this->contextWeights[$context] ?? 1.0;
        $contextualRisk = min($baseRisk * $contextWeight, 1.0);
        
        // Analyse comportementale
        $behavioralRisk = $this->analyzeBehavioral($features, $context);
        
        // Fusion des risques
        $finalRisk = $this->fuseRisks($contextualRisk, $behavioralRisk);
        
        // Calcul de la confiance
        $this->confidence = $this->calculateConfidence($features, $patternMatches);
        
        // Classification de la menace
        $threatType = $this->classifyThreat($patternMatches, $features);
        
        $processingTime = microtime(true) - $startTime;
        
        return [
            'risk' => round($finalRisk, 3),
            'confidence' => round($this->confidence, 3),
            'type' => $threatType,
            'features' => $features,
            'patterns' => array_keys($patternMatches),
            'context' => $context,
            'context_weight' => $contextWeight,
            'timestamp' => date('Y-m-d H:i:s'),
            'decision' => $finalRisk > self::RISK_THRESHOLD ? 'BLOCK' : 'ALLOW',
            'model_version' => self::MODEL_VERSION,
            'processing_time' => round($processingTime * 1000, 2),
            'request_id' => $this->requestId,
            'metadata' => [
                'input_length' => strlen($input),
                'normalized_length' => strlen($normalizedInput),
                'pattern_count' => count($patternMatches),
                'feature_count' => count($features)
            ],
            'recommendations' => $this->generateRecommendations($finalRisk, ['type' => $context])
        ];
    }
    
    /**
     * Analyse avancée avec paramètres supplémentaires
     * @param string $input Entrée à analyser
     * @param array $context Contexte de la requête
     * @param string|null $sessionId ID de session (optionnel)
     * @param string|null $ipAddress Adresse IP (optionnel)
     * @return array Résultat détaillé de l'analyse
     */
    public function analyzeAdvanced(
        string $input,
        array $context = [],
        ?string $sessionId = null,
        ?string $ipAddress = null
    ): array {
        $basicAnalysis = $this->analyze($input, $context['type'] ?? 'default');
        
        $advancedAnalysis = array_merge($basicAnalysis, [
            'session_analysis' => $sessionId !== null ? $this->analyzeSession($sessionId) : null,
            'ip_reputation' => $ipAddress !== null ? $this->checkIpReputation($ipAddress) : null,
            'geolocation' => $ipAddress !== null ? $this->getGeolocation($ipAddress) : null,
            'request_metadata' => $context,
            'risk_factors' => $this->identifyRiskFactors($input, $context),
            'recommendations' => $this->generateRecommendations($basicAnalysis['risk'], $context)
        ]);
        
        return $advancedAnalysis;
    }
    
    /**
     * Charge les modèles ML (simulé)
     */
    private function loadModels(): void
    {
        $this->mlModels = [
            'random_forest' => ['version' => '1.0', 'accuracy' => 0.94],
            'neural_network' => ['version' => '2.0', 'accuracy' => 0.96],
            'xgboost' => ['version' => '1.5', 'accuracy' => 0.95]
        ];
    }
    
    /**
     * Charge les patterns comportementaux
     */
    private function loadBehavioralPatterns(): void
    {
        $this->behavioralPatterns = [
            'rapid_requests' => 0.8,
            'multiple_failures' => 0.75,
            'unusual_hours' => 0.6,
            'geo_hopping' => 0.85,
            'user_agent_spoofing' => 0.7,
            'referer_spoofing' => 0.65
        ];
    }
    
    /**
     * Prédiction avec modèle ML (simulé)
     */
    private function predictWithML(array $features): array
    {
        if (!$this->useRealML || empty($this->mlModels)) {
            return $this->predictWithHeuristics($features);
        }
        
        $risk = 0.1;
        
        // Facteurs ML (simulés)
        if ($features['entropy'] > 4.0) $risk += 0.25;
        if ($features['special_char_ratio'] > 0.3) $risk += 0.30;
        if ($features['has_union_pattern']) $risk += 0.35;
        if ($features['has_time_based']) $risk += 0.20;
        
        $confidence = min(0.95, 0.5 + ($risk * 0.5));
        
        return [
            'risk' => min($risk, 1.0),
            'confidence' => $confidence,
            'model_used' => 'random_forest'
        ];
    }
    
    /**
     * Prédiction avec heuristiques (fallback)
     */
    private function predictWithHeuristics(array $features): array
    {
        $risk = 0.1;
        
        $riskFactors = [
            'has_union_pattern' => 0.25,
            'has_comment' => 0.20,
            'has_time_based' => 0.30,
            'has_tautology' => 0.25,
            'special_char_ratio' => 0.15,
            'entropy' => 0.20,
            'sql_keywords' => 0.10,
        ];
        
        foreach ($riskFactors as $feature => $weight) {
            if (isset($features[$feature]) && $features[$feature] > 0) {
                $risk += $weight * min($features[$feature], 1.0);
            }
        }
        
        if ($features['length'] > 200) $risk += 0.15;
        if ($features['keyword_density'] > 0.3) $risk += 0.25;
        
        $confidence = $this->calculateHeuristicConfidence($features);
        
        return [
            'risk' => min($risk, 1.0),
            'confidence' => $confidence,
            'model_used' => 'heuristic'
        ];
    }
    
    /**
     * Analyse comportementale (simulée)
     */
    private function analyzeBehavior(string $sessionId, array $features): float
    {
        $behaviorRisk = 0.0;
        
        $hour = (int)date('H');
        if ($hour >= 0 && $hour <= 5) {
            $behaviorRisk += 0.15;
        }
        
        $requestCount = rand(1, 100);
        if ($requestCount > 50) {
            $behaviorRisk += 0.20;
        }
        
        if ($features['length'] > 300) $behaviorRisk += 0.10;
        if ($features['entropy'] > 5.0) $behaviorRisk += 0.15;
        
        return min($behaviorRisk, 0.5);
    }
    
    /**
     * Fusionne les prédictions
     */
    private function fusePredictions(float $mlRisk, float $behavioralRisk, array $features): float
    {
        $fused = ($mlRisk * 0.6) + ($behavioralRisk * 0.4);
        $featureConfidence = $this->calculateFeatureConfidence($features);
        $adjusted = $fused * $featureConfidence;
        
        return min($adjusted, 1.0);
    }
    
    /**
     * Calcule la confiance de l'analyse
     */
    private function calculateConfidence(array $features, array $patternMatches): float
    {
        $confidence = 0.5;
        
        if (count($patternMatches) > 0) {
            $confidence += 0.25;
        }
        
        if ($features['sql_keywords'] > 2) {
            $confidence += 0.15;
        }
        
        if ($features['special_chars'] > 5) {
            $confidence += 0.10;
        }
        
        if ($features['entropy'] > 3.5) {
            $confidence += 0.10;
        }
        
        if ($features['length'] < 5) {
            $confidence -= 0.20;
        }
        
        return max(0.1, min($confidence, 0.95));
    }
    
    /**
     * Extraction de caractéristiques
     */
    private function extractFeatures(string $input): array
    {
        $features = [
            'length' => strlen($input),
            'word_count' => str_word_count($input),
            'special_chars' => preg_match_all('/[\'"=;#()\-*\/]/', $input) ?: 0,
            'digit_count' => preg_match_all('/\d/', $input) ?: 0,
            'letter_count' => preg_match_all('/[a-z]/i', $input) ?: 0,
            'sql_keywords' => $this->countKeywords($input, [
                'select', 'union', 'insert', 'update', 'delete', 'drop',
                'create', 'alter', 'from', 'where', 'and', 'or', 'join',
                'table', 'database', 'schema', 'column', 'index'
            ]),
            'has_parentheses' => (int)(strpos($input, '(') !== false),
            'has_semicolon' => (int)(strpos($input, ';') !== false),
            'has_comment' => (int)(preg_match('/--|#|\/\*/', $input) === 1),
            'has_quotes' => (int)(strpos($input, "'") !== false || strpos($input, '"') !== false),
            'entropy' => $this->calculateEntropy($input),
            'compressibility' => $this->calculateCompressibility($input),
            'token_diversity' => $this->calculateTokenDiversity($input),
            'char_frequency' => $this->getCharacterFrequency($input),
            'keyword_density' => $this->calculateKeywordDensity($input),
            'has_union_pattern' => (int)preg_match('/\bunion\b.*\bselect\b/i', $input) === 1,
            'has_tautology' => (int)preg_match('/\b(?:1=1|[\'"]1[\'"]=[\'"]1[\'"])\b/i', $input) === 1,
            'has_time_based' => (int)preg_match('/\b(?:sleep|benchmark|waitfor)\b/i', $input) === 1,
            'has_error_based' => (int)preg_match('/\b(?:extractvalue|updatexml|exp)\b/i', $input) === 1,
        ];
        
        if ($features['length'] > 0) {
            $features['special_char_ratio'] = $features['special_chars'] / $features['length'];
            $features['digit_ratio'] = $features['digit_count'] / $features['length'];
            $features['letter_ratio'] = $features['letter_count'] / $features['length'];
        } else {
            $features['special_char_ratio'] = 0;
            $features['digit_ratio'] = 0;
            $features['letter_ratio'] = 0;
        }
        
        return $features;
    }
    
    /**
     * Calcule l'entropie de Shannon
     */
    private function calculateEntropy(string $data): float
    {
        if (empty($data)) return 0.0;
        
        $entropy = 0.0;
        $len = strlen($data);
        $charCounts = [];
        
        for ($i = 0; $i < $len; $i++) {
            $char = $data[$i];
            $charCounts[$char] = ($charCounts[$char] ?? 0) + 1;
        }
        
        foreach ($charCounts as $count) {
            $probability = $count / $len;
            $entropy -= $probability * log($probability, 2);
        }
        
        return round($entropy, 2);
    }
    
    /**
     * Ratio de caractères spéciaux
     */
    private function calculateSpecialCharRatio(string $input): float
    {
        if (empty($input)) return 0.0;
        $specialChars = preg_match_all('/[^\w\s]/', $input) ?: 0;
        return round($specialChars / strlen($input), 3);
    }
    
    /**
     * Densité de mots-clés
     */
    private function calculateKeywordDensity(string $input): float
    {
        $tokens = preg_split('/\s+/', $input);
        $tokens = array_filter($tokens);
        
        if (empty($tokens)) return 0.0;
        
        $sqlKeywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'create', 'alter'];
        $keywordCount = 0;
        
        foreach ($tokens as $token) {
            if (in_array(strtolower($token), $sqlKeywords)) {
                $keywordCount++;
            }
        }
        
        return round($keywordCount / count($tokens), 3);
    }
    
    /**
     * Ratio de tokens uniques
     */
    private function calculateUniqueTokenRatio(string $input): float
    {
        $tokens = preg_split('/\s+/', $input);
        $tokens = array_filter($tokens);
        
        if (empty($tokens)) return 0.0;
        
        $uniqueTokens = array_unique($tokens);
        return round(count($uniqueTokens) / count($tokens), 3);
    }
    
    /**
     * Longueur moyenne des tokens
     */
    private function calculateAverageTokenLength(string $input): float
    {
        $tokens = preg_split('/\s+/', $input);
        $tokens = array_filter($tokens);
        
        if (empty($tokens)) return 0.0;
        
        $totalLength = 0;
        foreach ($tokens as $token) {
            $totalLength += strlen($token);
        }
        
        return round($totalLength / count($tokens), 2);
    }
    
    /**
     * Risque contextuel
     */
    private function getContextRisk(array $context): float
    {
        $contextType = $context['type'] ?? 'default';
        return $this->contextWeights[$contextType] ?? 1.0;
    }
    
    /**
     * Détection de pattern temporel
     */
    private function detectTimeBasedPattern(string $input): float
    {
        $patterns = ['sleep', 'benchmark', 'waitfor', 'delay'];
        $score = 0.0;
        
        foreach ($patterns as $pattern) {
            if (stripos($input, $pattern) !== false) {
                $score += 0.25;
            }
        }
        
        return min($score, 1.0);
    }
    
    /**
     * Détection de pattern basé sur les erreurs
     */
    private function detectErrorBasedPattern(string $input): float
    {
        $patterns = ['extractvalue', 'updatexml', 'exp', 'floor', 'rand'];
        $score = 0.0;
        
        foreach ($patterns as $pattern) {
            if (stripos($input, $pattern) !== false) {
                $score += 0.20;
            }
        }
        
        return min($score, 1.0);
    }
    
    /**
     * Détection de pattern booléen
     */
    private function detectBooleanBasedPattern(string $input): float
    {
        $patterns = ['1=1', "'1'='1'", 'or 1', 'and 1'];
        $score = 0.0;
        
        foreach ($patterns as $pattern) {
            if (stripos($input, $pattern) !== false) {
                $score += 0.30;
            }
        }
        
        return min($score, 1.0);
    }
    
    /**
     * Détection de couches d'encodage
     */
    private function detectEncodingLayers(string $input): int
    {
        $layers = 0;
        $decoded = $input;
        
        for ($i = 0; $i < 5; $i++) {
            $temp = urldecode($decoded);
            if ($temp === $decoded) break;
            $decoded = $temp;
            $layers++;
        }
        
        return $layers;
    }
    
    /**
     * Détection de variation d'espaces
     */
    private function detectWhitespaceVariation(string $input): float
    {
        $whitespaceCount = preg_match_all('/\s+/', $input) ?: 0;
        $totalChars = strlen($input);
        
        if ($totalChars === 0) return 0.0;
        
        $ratio = $whitespaceCount / $totalChars;
        return $ratio > 0.3 ? 0.8 : 0.0;
    }
    
    /**
     * Détection de variation de casse
     */
    private function detectCaseVariation(string $input): float
    {
        $upperCount = preg_match_all('/[A-Z]/', $input) ?: 0;
        $lowerCount = preg_match_all('/[a-z]/', $input) ?: 0;
        $totalLetters = $upperCount + $lowerCount;
        
        if ($totalLetters === 0) return 0.0;
        
        $variation = abs($upperCount - $lowerCount) / $totalLetters;
        return $variation > 0.7 ? 0.6 : 0.0;
    }
    
    /**
     * Extraction de features n-gram
     */
    private function extractNgramFeatures(string $input): array
    {
        $ngrams = [];
        $tokens = preg_split('/\s+/', $input);
        $tokens = array_filter($tokens);
        
        for ($i = 0; $i < count($tokens) - 1; $i++) {
            if (isset($tokens[$i], $tokens[$i + 1])) {
                $bigram = $tokens[$i] . ' ' . $tokens[$i + 1];
                $ngrams['bigram_' . md5($bigram)] = 1;
            }
        }
        
        return $ngrams;
    }
    
    /**
     * Confiance heuristique
     */
    private function calculateHeuristicConfidence(array $features): float
    {
        $confidence = 0.5;
        
        if ($features['length'] > 10) $confidence += 0.15;
        if ($features['sql_keywords'] > 0) $confidence += 0.20;
        if ($features['special_char_ratio'] > 0.1) $confidence += 0.10;
        if ($features['entropy'] > 3.0) $confidence += 0.15;
        
        return min($confidence, 0.95);
    }
    
    /**
     * Confiance des features
     */
    private function calculateFeatureConfidence(array $features): float
    {
        $confidence = 0.3;
        
        if ($features['length'] > 5) $confidence += 0.2;
        if ($features['word_count'] > 2) $confidence += 0.15;
        if ($features['special_chars'] > 0) $confidence += 0.1;
        if ($features['entropy'] > 2.0) $confidence += 0.1;
        
        return min($confidence, 0.9);
    }
    
    /**
     * Normalisation de l'entrée
     */
    private function normalizeInput(string $input): string
    {
        $decoded = $input;
        for ($i = 0; $i < 3; $i++) {
            $temp = urldecode($decoded);
            if ($temp === $decoded) break;
            $decoded = $temp;
        }
        
        $normalized = preg_replace('/\s+/', ' ', $decoded);
        $normalized = mb_strtolower($normalized, 'UTF-8');
        $normalized = preg_replace('/[\x00-\x09\x0B\x0C\x0E-\x1F\x7F]/', '', $normalized);
        
        return trim($normalized);
    }
    
    /**
     * Détection de patterns
     */
    private function detectPatterns(string $input): array
    {
        $matches = [];
        
        foreach ($this->threatPatterns as $pattern => $riskScore) {
            if (preg_match($pattern, $input)) {
                $matches[$pattern] = $riskScore;
            }
        }
        
        return $matches;
    }
    
    /**
     * Calcul du risque de base
     */
    private function calculateBaseRisk(array $patternMatches, array $features): float
    {
        $risk = 0.1;
        
        foreach ($patternMatches as $patternRisk) {
            $risk += $patternRisk * 0.15;
        }
        
        if ($features['has_union_pattern']) $risk += 0.25;
        if ($features['has_time_based']) $risk += 0.20;
        if ($features['has_error_based']) $risk += 0.18;
        if ($features['has_tautology']) $risk += 0.15;
        
        if ($features['special_char_ratio'] > 0.3) $risk += 0.20;
        if ($features['entropy'] > 4.5) $risk += 0.15;
        if ($features['sql_keywords'] > 3) $risk += 0.10 * $features['sql_keywords'];
        
        return min($risk, 1.0);
    }
    
    /**
     * Analyse comportementale
     */
    private function analyzeBehavioral(array $features, string $context): float
    {
        $behaviorRisk = 0.0;
        
        $hour = (int)date('H');
        if ($hour >= 0 && $hour <= 5) {
            $behaviorRisk += 0.10;
        }
        
        $contextLengthLimits = [
            'login' => 50,
            'search' => 100,
            'registration' => 80,
            'default' => 200
        ];
        
        $limit = $contextLengthLimits[$context] ?? $contextLengthLimits['default'];
        if ($features['length'] > $limit) {
            $behaviorRisk += 0.15;
        }
        
        if ($features['keyword_density'] > 0.4) {
            $behaviorRisk += 0.20;
        }
        
        return min($behaviorRisk, 0.3);
    }
    
    /**
     * Fusion des risques
     */
    private function fuseRisks(float $contextualRisk, float $behavioralRisk): float
    {
        return ($contextualRisk * 0.7) + ($behavioralRisk * 0.3);
    }
    
    /**
     * Classification des menaces
     */
    private function classifyThreat(array $patternMatches, array $features): string
    {
        if ($features['has_time_based']) return 'TIME_BASED_INJECTION';
        if ($features['has_error_based']) return 'ERROR_BASED_INJECTION';
        if ($features['has_union_pattern']) return 'UNION_BASED_INJECTION';
        if ($features['has_tautology']) return 'BOOLEAN_BASED_INJECTION';
        
        foreach ($patternMatches as $pattern => $risk) {
            if (strpos($pattern, 'UNION') !== false) return 'UNION_SQLi';
            if (strpos($pattern, 'SLEEP') !== false) return 'TIME_BASED_SQLi';
            if (strpos($pattern, 'DROP') !== false) return 'DESTRUCTIVE_SQLi';
            if (strpos($pattern, '--') !== false) return 'COMMENT_INJECTION';
        }
        
        if ($features['special_char_ratio'] > 0.4) return 'SUSPICIOUS_INPUT';
        if ($features['sql_keywords'] > 2) return 'SQL_KEYWORDS_DETECTED';
        
        return 'UNCLASSIFIED_THREAT';
    }
    
    /**
     * Compte les mots-clés
     */
    private function countKeywords(string $input, array $keywords): int
    {
        $count = 0;
        $lowerInput = strtolower($input);
        
        foreach ($keywords as $keyword) {
            if (preg_match('/\b' . preg_quote($keyword, '/') . '\b/', $lowerInput)) {
                $count++;
            }
        }
        
        return $count;
    }
    
    /**
     * Calcul de la compressibilité
     */
    private function calculateCompressibility(string $data): float
    {
        if (empty($data)) return 0.0;
        
        $compressed = @gzcompress($data, 9);
        if ($compressed === false) return 1.0;
        
        $originalSize = strlen($data);
        $compressedSize = strlen($compressed);
        
        return round($compressedSize / $originalSize, 3);
    }
    
    /**
     * Diversité des tokens
     */
    private function calculateTokenDiversity(string $input): float
    {
        $tokens = preg_split('/\s+/', $input);
        $tokens = array_filter($tokens);
        
        if (empty($tokens)) return 0.0;
        
        $uniqueTokens = array_unique($tokens);
        return round(count($uniqueTokens) / count($tokens), 3);
    }
    
    /**
     * Fréquence des caractères
     */
    private function getCharacterFrequency(string $input): array
    {
        $freq = [];
        $len = strlen($input);
        
        for ($i = 0; $i < $len; $i++) {
            $char = $input[$i];
            $freq[$char] = ($freq[$char] ?? 0) + 1;
        }
        
        arsort($freq);
        return array_slice($freq, 0, 10);
    }
    
    /**
     * Analyse de session (simulée)
     */
    private function analyzeSession(string $sessionId): array
    {
        return [
            'session_age' => rand(1, 3600),
            'request_count' => rand(1, 100),
            'suspicious_activities' => rand(0, 5),
            'location_changes' => rand(0, 3)
        ];
    }
    
    /**
     * Génération de recommandations
     */
    private function generateRecommendations(float $risk, array $context): array
    {
        $recommendations = [];
        
        if ($risk > 0.9) {
            $recommendations = ['IMMEDIATE_BLOCK', 'IP_BAN_24H', 'NOTIFY_SECURITY_TEAM', 'ENHANCE_LOGGING'];
        } elseif ($risk > 0.7) {
            $recommendations = ['BLOCK_REQUEST', 'CAPTCHA_CHALLENGE', 'RATE_LIMIT', 'DETAILED_LOG'];
        } elseif ($risk > 0.5) {
            $recommendations = ['WARNING', 'ENHANCED_MONITORING', 'SESSION_REVIEW'];
        } else {
            $recommendations = ['CONTINUE_MONITORING'];
        }
        
        $contextType = $context['type'] ?? 'default';
        if ($contextType === 'login') {
            $recommendations[] = 'MFA_SUGGESTION';
        }
        
        if (isset($context['failed_attempts']) && $context['failed_attempts'] > 3) {
            $recommendations[] = 'ACCOUNT_LOCK_TEMPORARY';
        }
        
        return $recommendations;
    }
    
    /**
     * Vérification de réputation IP (simulée)
     */
    private function checkIpReputation(string $ip): array
    {
        $isMalicious = preg_match('/^(127\.|10\.|192\.168\.)/', $ip) ? false : (rand(0, 100) > 90);
        
        return [
            'reputation_score' => $isMalicious ? rand(10, 40) : rand(60, 100),
            'abuse_count' => $isMalicious ? rand(1, 50) : 0,
            'country' => ['US', 'CN', 'RU', 'FR', 'DE'][rand(0, 4)],
            'is_tor' => rand(0, 100) > 95,
            'is_vpn' => rand(0, 100) > 85
        ];
    }
    
    /**
     * Géolocalisation (simulée)
     */
    private function getGeolocation(string $ip): array
    {
        $countries = ['FR', 'US', 'CN', 'DE', 'GB', 'RU', 'JP', 'BR'];
        $cities = ['Paris', 'New York', 'Beijing', 'Berlin', 'London', 'Moscow', 'Tokyo', 'São Paulo'];
        
        $index = rand(0, count($countries) - 1);
        
        return [
            'country' => $countries[$index],
            'country_name' => $this->getCountryName($countries[$index]),
            'city' => $cities[$index],
            'latitude' => round(rand(-9000, 9000) / 100, 2),
            'longitude' => round(rand(-18000, 18000) / 100, 2),
            'timezone' => 'UTC' . (rand(0, 1) ? '+' : '-') . rand(1, 12)
        ];
    }
    
    /**
     * Identification des facteurs de risque
     */
    private function identifyRiskFactors(string $input, array $context): array
    {
        $factors = [];
        
        if (strlen($input) > 500) $factors[] = 'EXCESSIVE_LENGTH';
        if (preg_match_all('/[\'"]/', $input) > 10) $factors[] = 'EXCESSIVE_QUOTES';
        if (preg_match_all('/\-\-/', $input) > 3) $factors[] = 'MULTIPLE_COMMENTS';
        
        if ($context['type'] === 'admin_panel') $factors[] = 'SENSITIVE_CONTEXT';
        if (isset($context['user_role']) && $context['user_role'] === 'admin') $factors[] = 'ADMIN_ACCESS';
        
        $hour = (int)date('H');
        if ($hour >= 0 && $hour <= 6) $factors[] = 'OFF_HOURS_ACCESS';
        
        return $factors;
    }
    
    /**
     * Nom du pays
     */
    private function getCountryName(string $code): string
    {
        $countries = [
            'FR' => 'France',
            'US' => 'United States',
            'CN' => 'China',
            'DE' => 'Germany',
            'GB' => 'United Kingdom',
            'RU' => 'Russia',
            'JP' => 'Japan',
            'BR' => 'Brazil'
        ];
        
        return $countries[$code] ?? 'Unknown';
    }
    
    /**
     * Test d'analyse
     */
    public function testAnalysis(string $input = "' OR '1'='1", string $context = 'login'): array
    {
        return $this->analyze($input, $context);
    }
    
    /**
     * Version du modèle
     */
    public function getModelVersion(): string
    {
        return self::MODEL_VERSION;
    }
    
    /**
     * Réinitialisation de l'ID de requête
     */
    public function resetRequestId(): void
    {
        $this->requestId = bin2hex(random_bytes(8));
    }
    
    /**
     * Vérifie si une entrée doit être bloquée
     */
    public function shouldBlock(array $analysisResult): bool
    {
        return $analysisResult['risk'] > self::RISK_THRESHOLD 
            && $analysisResult['confidence'] > 0.7;
    }
}