<?php
return [
    'block_mode' => getenv('CYBERSHIELD_MODE') !== 'monitor',
    'block_threshold' => 80,
    'review_threshold' => 30,
    'max_request_size' => 65536,
    'max_input_length' => 8192,
    'max_parameters' => 128,
    'max_ai_calls' => 4,
    'log_dir' => getenv('CYBERSHIELD_LOG_DIR') ?: __DIR__ . '/../logs',
    'rate_limiting' => ['enabled' => true, 'max_requests' => 100, 'window_seconds' => 60],
    'retention_days' => 90,
];
