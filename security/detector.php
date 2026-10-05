<?php
/** Local SQLi screening. It never replaces parameterized database queries. */
class SQLInjectionDetector
{
    private $blockMode = true;
    private $blockThreshold = 80;
    private $reviewThreshold = 30;
    private $patterns = [
        'UNION_SELECT' => ['~\bunion\s+(?:(?:all|distinct)\s+)?select\b~i', 95],
        'NUMERIC_BOOLEAN' => ['~\b(?:or|and)\s+(?:not\s+)?[+-]?\d+(?:\.\d+)?\s*(?:=|!=|<>|>=|<=|>|<)\s*[+-]?\d+(?:\.\d+)?\b~i', 90],
        'QUOTED_BOOLEAN' => ['~\b(?:or|and)\s+[\x27\x22][^\x27\x22\r\n]{1,80}[\x27\x22]\s*(?:=|!=|<>|like\b)\s*[\x27\x22][^\x27\x22\r\n]{1,80}~i', 90],
        'BOOLEAN_PREDICATE' => ['~\b(?:or|and)\s+(?:exists\s*\(|\d+\s+(?:between\s+\d+|in\s*\(|is\s+(?:not\s+)?null))~i', 90],
        'BOOLEAN_LITERAL' => ['~(?:[\x27\x22]\s*|\d+\s+)(?:or|and)\s+(?:true|false)\b~i', 90],
        'STACKED_STATEMENT' => ['~;\s*(?:drop|truncate|delete|insert|update|alter|create|exec(?:ute)?)\b~i', 100],
        'TIME_BASED' => ['~\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b~i', 95],
        'ERROR_BASED' => ['~\b(?:extractvalue|updatexml)\s*\(~i', 95],
        'FILE_ACCESS' => ['~\bload_file\s*\(|\binto\s+(?:out|dump)file\b~i', 95],
        'QUOTE_COMMENT' => ['~[\x27\x22]\s*(?:--|\#|/\*)~', 60],
        'SYSTEM_CATALOG' => ['~\b(?:information_schema|pg_catalog|sqlite_master|sysobjects)\b~i', 65],
        'SELECT_STATEMENT' => ['~\bselect\b[^;\r\n]{1,1000}\bfrom\b~i', 45],
        'WRITE_STATEMENT' => ['~\b(?:insert\s+into|delete\s+from|update\s+[\w`]+\s+set)\b~i', 60],
        'ENCODED_SQL_FUNCTION' => ['~\b(?:char|nchar|chr)\s*\(\s*\d+(?:\s*,\s*\d+)+\s*\)~i', 45],
    ];

    public function __construct($logger = null, array $config = [])
    {
        // Logging belongs to the final middleware decision, never intermediate rules.
        $this->blockMode = (bool) ($config['block_mode'] ?? true);
        $this->blockThreshold = max(1, min(100, (int) ($config['block_threshold'] ?? 80)));
        $this->reviewThreshold = max(1, min($this->blockThreshold, (int) ($config['review_threshold'] ?? 30)));
    }

    public function analyzeWithScore($input, $paramName = '', $context = '')
    {
        $score = 0;
        $detected = [];
        $normalized = is_string($input) ? $this->normalize($input) : '';
        // Both forms detect SQL tokens separated by comments and split inside a token.
        $variants = [$normalized];
        $variants[] = preg_replace('~/\*.*?\*/~s', ' ', $normalized);
        $variants[] = preg_replace('~/\*.*?\*/~s', '', $normalized);
        foreach ($this->patterns as $name => $rule) {
            foreach ($variants as $variant) {
                if (preg_match($rule[0], $variant) === 1) {
                    $detected[] = $name;
                    // Related signatures must not count the same evidence twice.
                    $score = max($score, $rule[1]);
                    break;
                }
            }
        }
        $wouldBlock = $score >= $this->blockThreshold;
        $needsAi = !$wouldBlock && $score >= $this->reviewThreshold;
        $sensitive = preg_match('/pass|pwd|token|secret|cookie|authorization|card|carte|cvv|cvc|csrf/i', (string) $paramName);
        return [
            'block' => $this->blockMode && $wouldBlock,
            'would_block' => $wouldBlock,
            'score' => $score,
            'patterns' => $detected,
            'needs_ai' => $needsAi,
            'decision' => $wouldBlock ? ($this->blockMode ? 'IMMEDIATE_BLOCK' : 'MONITORED') : ($needsAi ? 'NEEDS_AI_ANALYSIS' : 'LOW_RISK_ALLOWED'),
            'input_preview' => $sensitive ? '[REDACTED]' : substr($normalized, 0, 100),
        ];
    }

    private function normalize($input)
    {
        // rawurldecode preserves legitimate '+' characters. Bound decoding depth.
        for ($i = 0; $i < 3; $i++) {
            $decoded = rawurldecode($input);
            if ($decoded === $input) {
                break;
            }
            $input = $decoded;
        }
        $input = html_entity_decode($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $input = str_replace("\0", '', $input);
        if (strpos($input, '/*') !== false) {
            // Restore split keywords first; remaining comments separate SQL tokens.
            $comment = '(?:/\*[^*]*(?:\*(?!/)[^*]*)*\*/)*';
            foreach (['union', 'select', 'all', 'distinct', 'or', 'and', 'sleep', 'benchmark', 'drop', 'delete', 'from', 'where', 'insert', 'update'] as $keyword) {
                $pattern = '~\b' . implode($comment, str_split($keyword)) . '\b~i';
                $input = preg_replace($pattern, $keyword, $input);
            }
        }
        // MySQL executable comments contain actual SQL.
        return preg_replace('~/\*!\d{0,6}\s*(.*?)\*/~s', ' $1 ', $input);
    }

    public function detect($input, $paramName = '')
    {
        return $this->analyzeWithScore($input, $paramName)['block'];
    }

    public function setBlockMode($mode) { $this->blockMode = (bool) $mode; }
    public function getBlockMode() { return $this->blockMode; }
    public function getPatterns() { return array_keys($this->patterns); }

    /** Compatibility helper for HTML output, not an SQL injection defense. */
    public function sanitizeInput($input)
    {
        if (is_array($input)) {
            return array_map([$this, 'sanitizeInput'], $input);
        }
        return is_string($input) ? htmlspecialchars($input, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') : $input;
    }

    public function escapeSql($input, $connection = null)
    {
        if ($connection instanceof mysqli) {
            return $connection->real_escape_string($input);
        }
        throw new InvalidArgumentException('Une connexion SQL est requise ; utilisez des requêtes préparées.');
    }
}
