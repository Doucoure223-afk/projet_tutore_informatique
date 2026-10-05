<?php
declare(strict_types=1);

/**
 * Exemple de configuration. Copiez vers config.php et renseignez les valeurs.
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
        'site_key' => '',   // Clé site reCAPTCHA v2 (case « Je ne suis pas un robot »)
        'secret_key' => ''  // Clé secrète (ne pas commiter en production)
    ]
];
