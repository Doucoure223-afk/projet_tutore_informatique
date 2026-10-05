<?php

declare(strict_types=1);

namespace App\Infrastructure\Database;

use PDO;
use PDOException;
use RuntimeException;

/**
 * Pool de connexions haute performance avec gestion des réplicas en lecture
 */
final class ConnectionPool
{
    private static ?PDO $masterConnection = null;
    private static array $replicaConnections = [];
    private static int $currentReplicaIndex = 0;
    
    private const MAX_RETRIES = 3;
    private const RETRY_DELAY = 100; // ms
    
    /**
     * Obtient une connexion en écriture (master)
     */
    public static function getMaster(): PDO
    {
        if (self::$masterConnection === null) {
            self::$masterConnection = self::createConnection('master');
        }
        
        return self::$masterConnection;
    }
    
    /**
     * Obtient une connexion en lecture (replica) avec load balancing
     */
    public static function getReplica(): PDO
    {
        if (empty(self::$replicaConnections)) {
            self::$replicaConnections[] = self::createConnection('replica');
        }
        
        $connection = self::$replicaConnections[self::$currentReplicaIndex];
        self::$currentReplicaIndex = (self::$currentReplicaIndex + 1) % count(self::$replicaConnections);
        
        return $connection;
    }
    
    /**
     * Crée une connexion PDO avec retry logic
     */
    private static function createConnection(string $type): PDO
    {
        $config = self::getConfig($type);
        
        for ($attempt = 1; $attempt <= self::MAX_RETRIES; $attempt++) {
            try {
                $dsn = sprintf(
                    'mysql:host=%s;dbname=%s;port=%d;charset=utf8mb4',
                    $config['host'],
                    $config['database'],
                    $config['port'] ?? 3306
                );
                
                $pdo = new PDO(
                    $dsn,
                    $config['username'],
                    $config['password'],
                    [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                        PDO::ATTR_EMULATE_PREPARES => false,
                        PDO::ATTR_PERSISTENT => $config['persistent'] ?? false,
                        PDO::MYSQL_ATTR_INIT_COMMAND => "SET time_zone = '+00:00', sql_mode = 'STRICT_ALL_TABLES'",
                        PDO::MYSQL_ATTR_COMPRESS => $config['compress'] ?? true,
                    ]
                );
                
                // Test de la connexion
                $pdo->query('SELECT 1')->fetch();
                
                return $pdo;
                
            } catch (PDOException $e) {
                if ($attempt === self::MAX_RETRIES) {
                    throw new RuntimeException(
                        sprintf('Échec de connexion %s après %d tentatives: %s', 
                            $type, self::MAX_RETRIES, $e->getMessage())
                    );
                }
                
                usleep(self::RETRY_DELAY * 1000 * $attempt); // Backoff exponentiel
            }
        }
        
        throw new RuntimeException('Échec de création de connexion');
    }
    
    /**
     * Configuration intelligente selon l'environnement
     */
// Dans ConnectionPool.php, remplacer la méthode getConfig() par :

private static function getConfig(string $type): array
{
    // Charger la configuration depuis database.php
    $configFile = __DIR__ . '/../../../config/database.php';
    
    if (file_exists($configFile)) {
        $config = require $configFile;
        $mysqlConfig = $config['connections']['mysql'];
        
        return [
            'host' => $mysqlConfig['host'],
            'database' => $mysqlConfig['database'],
            'username' => $mysqlConfig['username'],
            'password' => $mysqlConfig['password'],
            'port' => $mysqlConfig['port'] ?? 3306,
            'persistent' => true,
            'compress' => true,
        ];
    }
    
    // Configuration par défaut si le fichier n'existe pas
    return [
        'host' => 'localhost',
        'database' => 'mon_projet_securite',
        'username' => 'root',
        'password' => '',
        'port' => 3306,
        'persistent' => false,
        'compress' => false,
    ];
}
    
    /**
     * Nettoie toutes les connexions
     */
    public static function closeAll(): void
    {
        self::$masterConnection = null;
        self::$replicaConnections = [];
        self::$currentReplicaIndex = 0;
    }
    
    /**
     * Vérifie la santé des connexions
     */
    public static function healthCheck(): array
    {
        $health = [
            'master' => false,
            'replicas' => [],
            'timestamp' => date('c'),
        ];
        
        try {
            self::getMaster()->query('SELECT 1')->fetch();
            $health['master'] = true;
        } catch (PDOException) {
            $health['master'] = false;
        }
        
        foreach (self::$replicaConnections as $index => $connection) {
            try {
                $connection->query('SELECT 1')->fetch();
                $health['replicas'][$index] = true;
            } catch (PDOException) {
                $health['replicas'][$index] = false;
            }
        }
        
        return $health;
    }
}