<?php
return [
    'block_mode' => true,
    'learning_mode' => false,
    'threshold' => 70,
    'whitelist_ips' => [
        '127.0.0.1',
        '::1'
    ],
    'excluded_paths' => [
        '/health',
        '/status',
        '/robots.txt',
        '/favicon.ico'
    ],
    'max_request_size' => 1048576,
    'rate_limiting' => [
        'enabled' => true,
        'max_requests' => 100,
        'window_seconds' => 60
    ]
];