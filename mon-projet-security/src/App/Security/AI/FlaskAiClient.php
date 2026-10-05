<?php

declare(strict_types=1);

namespace App\Security\AI;

/**
 * Client HTTP pour l'API IA Flask (Module SQL Injection).
 * Appelé par le middleware lorsque needsAiAnalysis est true.
 * En cas d'échec (timeout, API indisponible), le middleware utilise ThreatIntelligenceEngine en secours.
 */
final class FlaskAiClient
{
    private const TIMEOUT_SECONDS = 2;
    private const CONNECT_TIMEOUT_SECONDS = 1;

    public function __construct(
        private string $baseUrl,
        private ?\Psr\Log\LoggerInterface $logger = null
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    /**
     * Analyse une entrée via l'API Flask.
     *
     * @return array{risk: float, confidence: float, type: string}|null null en cas d'échec
     */
    public function analyze(string $input, array $context, ?string $sessionId = null): ?array
    {
        $url = $this->baseUrl . '/analyze';
        $payload = [
            'input' => $input,
            'context' => $context,
            'session_id' => $sessionId,
        ];

        $json = json_encode($payload, JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            return null;
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\n",
                'content' => $json,
                'timeout' => self::TIMEOUT_SECONDS,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);

        $response = @file_get_contents($url, false, $context);
        if ($response === false) {
            if ($this->logger !== null) {
                $this->logger->warning('FlaskAiClient: API indisponible ou timeout', ['url' => $url]);
            }
            return null;
        }

        $data = json_decode($response, true);
        if (!is_array($data) || !isset($data['risk']) || !isset($data['confidence']) || !isset($data['type'])) {
            if ($this->logger !== null) {
                $this->logger->warning('FlaskAiClient: réponse invalide', ['url' => $url]);
            }
            return null;
        }

        $result = [
            'risk' => (float) $data['risk'],
            'confidence' => (float) $data['confidence'],
            'type' => (string) $data['type'],
        ];
        if (!empty($data['risk_factors']) && is_array($data['risk_factors'])) {
            $result['risk_factors'] = $data['risk_factors'];
        }
        return $result;
    }

    /**
     * Vérifie si l'API est joignable (GET /health).
     */
    public function isAvailable(): bool
    {
        $url = $this->baseUrl . '/health';
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => self::CONNECT_TIMEOUT_SECONDS,
                'ignore_errors' => true,
            ],
        ]);
        $response = @file_get_contents($url, false, $context);
        if ($response === false) {
            return false;
        }
        $data = json_decode($response, true);
        return is_array($data) && ($data['status'] ?? '') === 'ok';
    }
}
