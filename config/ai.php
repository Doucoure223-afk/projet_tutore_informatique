<?php
return [
    'url' => getenv('CYBERSHIELD_AI_URL') ?: 'http://127.0.0.1:5000',
    'timeout_ms' => 900,
    'connect_timeout_ms' => 200,
    'threshold' => 0.75,
];
