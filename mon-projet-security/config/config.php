<?php
declare(strict_types=1);

/**
 * Configuration de l'application.
 * Copiez ce fichier depuis config.example.php si besoin, puis renseignez les clés reCAPTCHA.
 */
return [
    'app' => [
        'name' => 'Mon Projet Sécurité',
        'url' => 'http://localhost:8000'
    ],
    'database' => [
        'host' => getenv('DB_HOST') ?: 'localhost',
        'port' => getenv('DB_PORT') ?: '3306',
        'dbname' => getenv('DB_NAME') ?: 'mon_projet_securite',
        'username' => getenv('DB_USER') ?: 'root',
        'password' => getenv('DB_PASSWORD') ?: '',
        'charset' => 'utf8mb4'
    ],
    'mail' => [
        'from' => 'noreply@example.com',
        'from_name' => 'Mon Projet Sécurité'
    ],
    'ai' => [
        'flask_url' => 'http://127.0.0.1:5000'
    ],
    'recaptcha' => [
        // reCAPTCHA v2 (case « Je ne suis pas un robot »)
        'site_key' => '6LfIdGAsAAAAAOUHGRT1h9wgIa6ym7OJshcAMLvI',
        'secret_key' => '6LfIdGAsAAAAAFCBOIuUMuUsHNLQa5fqtfHrqSfM'
    ]
];
