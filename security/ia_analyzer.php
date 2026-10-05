<?php
/** Client for the real local MLP. An unavailable model is an explicit failure. */
class AIAnalyzer
{
    private array $config;

    public function __construct(?array $config = null)
    {
        $this->config = $config ?? require __DIR__ . '/../config/ai.php';
        $parts = parse_url($this->config['url']);
        if (!$parts || ($parts['scheme'] ?? '') !== 'http' ||
            !in_array($parts['host'] ?? '', ['127.0.0.1', 'localhost', '[::1]'], true) ||
            isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new InvalidArgumentException('Le service IA doit utiliser une adresse HTTP locale.');
        }
    }

    private function request(string $path, ?array $data = null): array
    {
        if (!extension_loaded('curl')) { throw new RuntimeException('Extension curl indisponible.'); }
        $curl = curl_init(rtrim($this->config['url'], '/') . $path);
        $body = '';
        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT_MS => $this->config['connect_timeout_ms'],
            CURLOPT_TIMEOUT_MS => $this->config['timeout_ms'], CURLOPT_PROXY => '',
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json'],
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > 65536) { return 0; }
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        if ($data !== null) {
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data, JSON_THROW_ON_ERROR));
        }
        $ok = curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);
        if ($ok === false || $status !== 200) { throw new RuntimeException('Service IA indisponible.'); }
        $result = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($result)) { throw new RuntimeException('Réponse IA invalide.'); }
        return $result;
    }

    public function analyze($sqlQuery, $context = 'unknown'): array
    {
        $result = $this->request('/analyse', ['sql' => $sqlQuery, 'context' => $context]);
        foreach (['risk', 'confidence'] as $field) {
            if (!isset($result[$field]) || !is_numeric($result[$field]) ||
                !is_finite((float) $result[$field]) || $result[$field] < 0 || $result[$field] > 1) {
                throw new RuntimeException('Score IA invalide.');
            }
        }
        if (($result['analysis_method'] ?? '') !== 'MLP' || empty($result['model_version']) ||
            !is_string($result['model_version'])) { throw new RuntimeException('Modèle IA non identifié.'); }
        $result['decision'] = $this->shouldBlock($result) ? 'BLOCK' : 'ALLOW';
        return $result;
    }

    public function shouldBlock($result): bool { return $result['risk'] >= $this->config['threshold']; }

    public function health(): array
    {
        try {
            $result = $this->request('/health');
            if (($result['model_loaded'] ?? false) !== true || ($result['analysis_method'] ?? '') !== 'MLP') {
                throw new RuntimeException('Modèle indisponible.');
            }
            return $result;
        } catch (Throwable $e) {
            return ['status' => 'unavailable', 'model_loaded' => false, 'model_version' => null];
        }
    }
}
