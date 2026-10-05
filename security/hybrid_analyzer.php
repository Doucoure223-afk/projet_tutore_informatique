<?php
require_once __DIR__ . '/detector.php';
require_once __DIR__ . '/ia_analyzer.php';

/** Immediate signatures first, bounded MLP pre-screen, strict fail-safe on errors. */
class HybridAnalyzer
{
    private SQLInjectionDetector $detector;
    private AIAnalyzer $ai;
    private array $config;

    public function __construct(?SQLInjectionDetector $detector = null, ?AIAnalyzer $ai = null, ?array $config = null)
    {
        $this->config = $config ?? require __DIR__ . '/../config/security.php';
        $this->detector = $detector ?? new SQLInjectionDetector(null, $this->config);
        $this->ai = $ai ?? new AIAnalyzer();
    }

    public function analyze(string $input, string $parameter = '', string $context = 'search', bool $allowAi = true, bool $preScreen = false): array
    {
        $start = microtime(true);
        $result = $this->detector->analyzeWithScore($input, $parameter, $context);
        $result += ['risk' => null, 'confidence' => null, 'source' => 'heuristic',
            'ai_status' => 'not_requested', 'model_version' => '',
            'attack_type' => $result['patterns'][0] ?? 'NONE', 'reason' => 'Aucun indice SQLi significatif.'];
        $block = $result['would_block'];
        if ($block) { $result['reason'] = 'Une signature SQLi explicite dépasse le seuil de blocage.'; }
        // Broaden model coverage to the first few request values even when
        // no PHP signature matched. Middleware bounds these calls per request.
        if ($result['needs_ai'] || ($preScreen && !$block)) {
            $result['needs_ai'] = true;
            try {
                if (!$allowAi) { throw new RuntimeException('Budget IA de la requête atteint.'); }
                $prediction = $this->ai->analyze($input, $context);
                $block = $this->ai->shouldBlock($prediction);
                $result['source'] = 'mlp';
                $result['ai_status'] = 'available';
                $result['risk'] = (float) $prediction['risk'];
                $result['confidence'] = (float) $prediction['confidence'];
                $result['model_version'] = $prediction['model_version'];
                $result['reason'] = $block ? 'Le score du MLP atteint le seuil de 0,75.' : 'Le score du MLP reste sous le seuil de 0,75.';
            } catch (Throwable $error) {
                $block = true;
                $result['source'] = 'fail_safe';
                $result['ai_status'] = $allowAi ? 'unavailable' : 'budget_exceeded';
                $result['reason'] = 'Cas ambigu bloqué par précaution : analyse IA indisponible.';
            }
        }
        $result['would_block'] = $block;
        $result['block'] = $block && $this->config['block_mode'];
        $result['action'] = !$block ? 'ALLOWED' : (!$this->config['block_mode'] ? 'MONITORED' : ($result['source'] === 'mlp' ? 'BLOCKED_BY_AI' : 'BLOCKED'));
        $result['decision'] = $result['block'] ? 'BLOCK' : 'ALLOW';
        $result['latency_ms'] = round((microtime(true) - $start) * 1000, 2);
        return $result;
    }
}
