<?php
declare(strict_types=1);

namespace App\Infrastructure;

use PDO;
use PDOException;
use Dotenv\Dotenv;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

/**
 * Configuration d'application moderne avec sécurité avancée
 */
final class ApplicationConfig
{
    private static ?PDO $pdo = null;
    private static ?Logger $logger = null;
    private static array $config = [];
    
    public static function initialize(string $rootPath): void
    {
        // Chargement des variables d'environnement
        $dotenv = Dotenv::createImmutable($rootPath);
        $dotenv->safeLoad();
        
        // Configuration de base
        self::$config = [
            'env' => $_ENV['APP_ENV'] ?? 'production',
            'debug' => ($_ENV['APP_DEBUG'] ?? '0') === '1',
            'url' => $_ENV['APP_URL'] ?? 'http://localhost',
            'timezone' => $_ENV['APP_TIMEZONE'] ?? 'UTC',
            'locale' => $_ENV['APP_LOCALE'] ?? 'fr_FR',
            
            // Sécurité
            'cipher' => 'AES-256-GCM',
            'key' => $_ENV['APP_KEY'] ?? '',
            'maintenance' => $_ENV['APP_MAINTENANCE'] ?? '0',
            
            // Base de données
            'database' => [
                'driver' => $_ENV['DB_CONNECTION'] ?? 'mysql',
                'host' => $_ENV['DB_HOST'] ?? '127.0.0.1',
                'port' => $_ENV['DB_PORT'] ?? '3306',
                'database' => $_ENV['DB_DATABASE'] ?? 'forge',
                'username' => $_ENV['DB_USERNAME'] ?? 'forge',
                'password' => $_ENV['DB_PASSWORD'] ?? '',
                'charset' => 'utf8mb4',
                'collation' => 'utf8mb4_unicode_ci',
                'prefix' => '',
                'strict' => true,
                'engine' => null,
                'options' => [
                    PDO::ATTR_EMULATE_PREPARES => false,
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_PERSISTENT => false,
                    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
                    PDO::MYSQL_ATTR_SSL_CA => $_ENV['MYSQL_ATTR_SSL_CA'] ?? null,
                    PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
                ]
            ],
            
            // Session sécurisée
            'session' => [
                'name' => '_secure_session',
                'lifetime' => (int)($_ENV['SESSION_LIFETIME'] ?? 120),
                'path' => '/',
                'domain' => $_ENV['SESSION_DOMAIN'] ?? null,
                'secure' => isset($_SERVER['HTTPS']),
                'httponly' => true,
                'samesite' => 'Strict'
            ],
            
            // Taux limite
            'rate_limiting' => [
                'enabled' => true,
                'max_attempts' => 60,
                'decay_minutes' => 1
            ],
            
            // CORS
            'cors' => [
                'allowed_origins' => explode(',', $_ENV['CORS_ALLOWED_ORIGINS'] ?? ''),
                'allowed_methods' => ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
                'allowed_headers' => ['Content-Type', 'Authorization', 'X-Requested-With'],
                'max_age' => 86400
            ]
        ];
        
        // Configuration du fuseau horaire
        date_default_timezone_set(self::$config['timezone']);
        
        // Démarrage de session sécurisée
        self::startSecureSession();
    }
    
    public static function getDatabase(): PDO
    {
        if (self::$pdo === null) {
            $dbConfig = self::$config['database'];
            
            $dsn = sprintf(
                '%s:host=%s;port=%s;dbname=%s;charset=%s',
                $dbConfig['driver'],
                $dbConfig['host'],
                $dbConfig['port'],
                $dbConfig['database'],
                $dbConfig['charset']
            );
            
            try {
                self::$pdo = new PDO(
                    $dsn,
                    $dbConfig['username'],
                    $dbConfig['password'],
                    $dbConfig['options']
                );
                
                // Optimisations spécifiques MySQL
                if ($dbConfig['driver'] === 'mysql') {
                    self::$pdo->exec("SET sql_mode = 'STRICT_ALL_TABLES'");
                    self::$pdo->exec("SET time_zone = '+00:00'");
                }
            } catch (PDOException $e) {
                error_log('Database connection failed: ' . $e->getMessage());
                throw new \RuntimeException(
                    'Database connection failed. Check configuration.',
                    0,
                    $e
                );
            }
        }
        
        return self::$pdo;
    }
    
    public static function getLogger(string $channel = 'application'): Logger
    {
        if (self::$logger === null) {
            $logPath = self::getLogPath();
            
            self::$logger = new Logger($channel);
            self::$logger->pushHandler(
                new StreamHandler(
                    $logPath . '/' . $channel . '.log',
                    self::isDebug() ? Logger::DEBUG : Logger::INFO
                )
            );
            
            // Handler pour erreurs critiques
            self::$logger->pushHandler(
                new StreamHandler(
                    $logPath . '/critical.log',
                    Logger::CRITICAL
                )
            );
        }
        
        return self::$logger;
    }
    
    public static function startSecureSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            $sessionConfig = self::$config['session'];
            
            session_set_cookie_params([
                'lifetime' => $sessionConfig['lifetime'] * 60,
                'path' => $sessionConfig['path'],
                'domain' => $sessionConfig['domain'],
                'secure' => $sessionConfig['secure'],
                'httponly' => $sessionConfig['httponly'],
                'samesite' => $sessionConfig['samesite']
            ]);
            
            session_name($sessionConfig['name']);
            session_start();
            
            // Régénération périodique de l'ID de session
            if (!isset($_SESSION['created'])) {
                $_SESSION['created'] = time();
            } elseif (time() - $_SESSION['created'] > 1800) {
                session_regenerate_id(true);
                $_SESSION['created'] = time();
            }
            
            // Protection contre le vol de session
            $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
            $_SESSION['ua'] = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
        }
    }
    
    public static function validateSession(): bool
    {
        if (empty($_SESSION['ip']) || empty($_SESSION['ua'])) {
            return false;
        }
        
        return $_SESSION['ip'] === $_SERVER['REMOTE_ADDR'] &&
               $_SESSION['ua'] === hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
    }
    
    public static function generateCsrfToken(): string
    {
        if (empty($_SESSION['csrf_tokens'])) {
            $_SESSION['csrf_tokens'] = [];
        }
        
        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_tokens'][$token] = time();
        
        // Nettoyage des anciens tokens
        $maxAge = 3600; // 1 heure
        foreach ($_SESSION['csrf_tokens'] as $storedToken => $timestamp) {
            if (time() - $timestamp > $maxAge) {
                unset($_SESSION['csrf_tokens'][$storedToken]);
            }
        }
        
        return $token;
    }
    
    public static function validateCsrfToken(string $token): bool
    {
        if (empty($_SESSION['csrf_tokens'][$token])) {
            return false;
        }
        
        $timestamp = $_SESSION['csrf_tokens'][$token];
        unset($_SESSION['csrf_tokens'][$token]);
        
        return time() - $timestamp < 3600; // Token valide 1 heure
    }
    
    public static function isDebug(): bool
    {
        return self::$config['debug'];
    }
    
    public static function isProduction(): bool
    {
        return self::$config['env'] === 'production';
    }
    
    public static function get(string $key, $default = null)
    {
        return self::$config[$key] ?? $default;
    }
    
    private static function getLogPath(): string
    {
        $path = $_ENV['LOG_PATH'] ?? __DIR__ . '/../../var/logs';
        
        if (!is_dir($path)) {
            mkdir($path, 0755, true);
        }
        
        return $path;
    }
}