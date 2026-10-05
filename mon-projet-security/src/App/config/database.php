<?php

declare(strict_types=1);

/**
 * Configuration de la base de données
 * Version standalone - sans dépendance externe
 */

// Fonction helper pour lire les variables d'environnement
if (!function_exists('env')) {
    function env(string $key, $default = null)
    {
        // 1. Vérifie dans $_ENV (si disponible)
        if (isset($_ENV[$key])) {
            return $_ENV[$key];
        }
        
        // 2. Vérifie dans getenv()
        $value = getenv($key);
        if ($value !== false) {
            return $value;
        }
        
        // 3. Vérifie dans $_SERVER (fallback)
        if (isset($_SERVER[$key])) {
            return $_SERVER[$key];
        }
        
        // 4. Retourne la valeur par défaut
        return $default;
    }
}

return [
    'default' => env('DB_CONNECTION', 'mysql'),
    
    'connections' => [
        'mysql' => [
            'driver' => 'mysql',
            'host' => env('DB_HOST', '127.0.0.1'),
            'port' => env('DB_PORT', '3306'),
            'database' => env('DB_DATABASE', 'mon_projet_securite'),
            'username' => env('DB_USERNAME', 'root'),
            'password' => env('DB_PASSWORD', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => true,
            'engine' => 'InnoDB',
        ],
    ],
    
    'redis' => [
        'default' => [
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'password' => env('REDIS_PASSWORD', null),
            'port' => env('REDIS_PORT', 6379),
            'database' => env('REDIS_DB', 0),
        ],
    ],
];