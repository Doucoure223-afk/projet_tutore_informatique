<?php
return [
    'log_dir' => __DIR__ . '/../logs',
    'max_file_size' => 10485760,
    'max_files' => 30,
    'log_level' => 'INFO',
    'outputs' => ['file', 'database'],
    'database' => [
        'enabled' => true,
        'table' => 'security_logs',
        'connection' => null // null pour utiliser la connexion par défaut
    ],
    'syslog' => [
        'enabled' => false,
        'facility' => LOG_USER,
        'ident' => 'sql_protection'
    ],
    'email' => [
        'enabled' => false,
        'recipients' => ['admin@example.com'],
        'threshold' => 'ERROR'
    ]
];