<?php
declare(strict_types=1);

namespace App\Security\Detector;

use Psr\Log\LoggerInterface;

/**
 * Détecteur SQL Injection avec scoring intelligent et contexte
 * Conforme OWASP 2026, PSR-12, utilise stratégies multiples
 */
final class SqlInjectionDetector{
    private const PATTERNS = [
        // Injection basique (score 100) — avec ou sans espace après la quote
        "/'\s*OR\s*'1'=[']?1/i" => 100,
        "/' OR 1=1[\s\-\-#]/i" => 100,
        "/' UNION[\s\W]*SELECT/i" => 100,
        "/' UNION ALL SELECT/i" => 100,
        "/' (?:AND|OR) '1'='1/i" => 100,
        
        // Destructif (score 120)
        "/'; (?:DROP|DELETE|TRUNCATE) /i" => 120,
        "/' OR SLEEP\(/i" => 120,
        "/' OR BENCHMARK\(/i" => 120,
        "/' OR WAITFOR DELAY /i" => 120,
        
        // Commentaires et evasion (score 80)
        "/'?--[\s\S]*$/i" => 80,
        "/'?#[\s\S]*$/i" => 80,
        "/\/\*[\s\S]*\*\//i" => 80,
        
        // Blind injection (score 90)
        "/' (?:AND|OR) \d+=\d+/i" => 90,
        "/' (?:AND|OR) '[^']+'='[^']+'/i" => 90,
        
        // Mots-clés suspects (score 60)
        "/\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*\b(?:FROM|INTO|TABLE)\b/i" => 60,
        "/\b(?:DATABASE|SCHEMA|VERSION|USER|PASSWORD)\b\(\)/i" => 60,
    ];
    
    private array $contextWeights = [
        'login' => 1.3,
        'registration' => 1.2,
        'search' => 1.1,
        'admin' => 1.5,
        'api' => 1.4,
        'default' => 1.0
    ];
    
    public function __construct(
        private ?LoggerInterface $logger = null,
        private bool $blockMode = true
    ) {}
    
    /**
     * Analyse une entrée avec scoring contextualisé
     */
    public function analyze(string $input, string $parameter = '', string $context = 'default'): DetectionResult
    {
        $input = $this->normalizeInput($input);
        $score = $this->calculateScore($input);
        $patterns = $this->detectPatterns($input);
        
        // Appliquer le contexte
        $contextWeight = $this->contextWeights[$context] ?? 1.0;
        $adjustedScore = (int)($score * $contextWeight);
        
        // Zone grise [30, 80[ : on délègue à l'IA (API Flask) ; blocage seulement si score >= 80
        $needsAiAnalysis = $adjustedScore >= 30 && $adjustedScore < 80;
        $shouldBlock = $adjustedScore >= 80;
        
        return new DetectionResult(
            score: $adjustedScore,
            shouldBlock: $shouldBlock,
            needsAiAnalysis: $needsAiAnalysis,
            detectedPatterns: $patterns,
            riskLevel: $this->determineRiskLevel($adjustedScore),
            context: $context
        );
    }
    
    private function normalizeInput(string $input): string
    {
        // Décodage multi-niveaux pour contrer l'évasion
        $normalized = $input;
        $depth = 0;
        
        while ($depth < 3) {
            $decoded = urldecode($normalized);
            if ($decoded === $normalized) break;
            $normalized = $decoded;
            $depth++;
        }
        
        // Suppression des espaces multiples et normalisation
        $normalized = preg_replace('/\s+/', ' ', $normalized);
        $normalized = mb_strtolower($normalized, 'UTF-8');
        
        return trim($normalized);
    }
    
    private function calculateScore(string $input): int
    {
        $score = 0;
        
        // 1. Pattern matching
        // On prend le score le plus élevé trouvé (et non la somme) pour éviter les surscores trop faciles.
        $maxPatternScore = 0;
        $matchesCount = 0;

        foreach (self::PATTERNS as $pattern => $patternScore) {
            if (preg_match($pattern, $input)) {
                $matchesCount++;
                $maxPatternScore = max($maxPatternScore, $patternScore);
            }
        }

        // Si on détecte un pattern de type “100” (ex. OR 1=1, UNION SELECT),
        // on le ramène en dessous du seuil de blocage strict pour laisser l'IA
        // analyser le cas (tout en gardant un niveau de suspicion élevé).
        if ($maxPatternScore >= 100 && $maxPatternScore < 120) {
            $maxPatternScore = 70;
        }

        $score += $maxPatternScore;
        if ($matchesCount > 1) {
            // Plusieurs patterns détectés : on ajoute un petit bonus sans exploser le score.
            $score += 10;
        }
        
        // 2. Analyse statistique
        $specialChars = preg_match_all('/[\'"=;#()\-\*]/', $input);
        if ($specialChars > 2) {
            // Limiter l’impact des caractères spéciaux pour ne pas dépasser trop vite 80.
            $score += min(($specialChars - 2) * 5, 20);
        }
        
        // 3. Longueur anormale
        $length = mb_strlen($input);
        if ($length > 100) $score += 20;
        if ($length > 250) $score += 30;
        
        // 4. Entropie élevée (caractères aléatoires)
        $entropy = $this->calculateShannonEntropy($input);
        if ($entropy > 4.5) $score += 25;
        
        return min($score, 150); // Cap à 150
    }
    
    private function detectPatterns(string $input): array
    {
        $detected = [];
        
        foreach (self::PATTERNS as $pattern => $score) {
            if (preg_match($pattern, $input)) {
                $detected[] = [
                    'pattern' => $pattern,
                    'score' => $score,
                    'matches' => $this->getPatternMatches($pattern, $input)
                ];
            }
        }
        
        return $detected;
    }
        /**
     * Récupère les correspondances exactes d’un pattern regex
     */
    private function getPatternMatches(string $pattern, string $input): array
    {
        $matches = [];

        preg_match_all($pattern, $input, $results);

        if (!empty($results[0])) {
            $matches = array_values(array_unique($results[0]));
        }

        return $matches;
    }

    private function determineRiskLevel(int $score): string
    {
        return match (true) {
            $score >= 100 => 'CRITICAL',
            $score >= 80 => 'HIGH',
            $score >= 50 => 'MEDIUM',
            $score >= 30 => 'LOW',
            default => 'NONE'
        };
    }
    
    private function calculateShannonEntropy(string $data): float
    {
        $len = strlen($data);
        if ($len === 0) return 0.0;
        
        $entropy = 0.0;
        $frequency = [];
        
        for ($i = 0; $i < $len; $i++) {
            $char = $data[$i];
            $frequency[$char] = ($frequency[$char] ?? 0) + 1;
        }
        
        foreach ($frequency as $freq) {
            $p = $freq / $len;
            $entropy -= $p * log($p, 2);
        }
        
        return round($entropy, 2);
    }
    
    public function setBlockMode(bool $mode): void
    {
        $this->blockMode = $mode;
    }
}

/**
 * DTO pour le résultat de détection
 */
final class DetectionResult
{
    public function __construct(
        public readonly int $score,
        public readonly bool $shouldBlock,
        public readonly bool $needsAiAnalysis,
        public readonly array $detectedPatterns,
        public readonly string $riskLevel,
        public readonly string $context
    ) {}
}