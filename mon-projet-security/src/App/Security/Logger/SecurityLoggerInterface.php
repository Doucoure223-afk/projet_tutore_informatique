<?php

namespace App\Security\Logger;

use Psr\Log\LoggerInterface;

interface SecurityLoggerInterface extends LoggerInterface
{
    public function logSqlInjection(
        string $ipAddress,
        string $payload,
        int $score,
        array $patterns,
        string $action,
        string $parameter = '',
        string $context = 'unknown'
    ): void;
    
    public function logAiAnalysis(
        string $requestId,
        array $features,
        array $prediction,
        float $processingTime
    ): void;
}