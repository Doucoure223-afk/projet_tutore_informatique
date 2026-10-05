<?php
declare(strict_types=1);

namespace App\Infrastructure;


use App\Security\Logger\SecurityLogger;
use Monolog\Level;
use Psr\Log\LoggerInterface;

use PDO;
use PDOException;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

final class ApplicationConfig
{
    private static ?PDO $database = null;
    private static array $config = [];
    private static array $loggers = [];

    public static function initialize(string $rootPath): void
    {
        $base = realpath($rootPath);
        if ($base === false) {
            $base = rtrim(str_replace('\\', '/', $rootPath), '/');
        }
        $configFile = $base . '/config/config.php';

        self::$config = file_exists($configFile)
            ? require $configFile
            : [
                'app' => [
                    'name' => 'Mon Projet Sécurité',
                    'url' => 'http://localhost:8000'
                ],
                'database' => [
                    'host' => 'localhost',
                    'port' => '3306',
                    'dbname' => 'mon_projet_securite',
                    'username' => 'root',
                    'password' => '',
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
                    'site_key' => '',
                    'secret_key' => ''
                ]
            ];
    }

    public static function getDatabase(): PDO
    {
        if (self::$database === null) {
            $db = self::$config['database'];

            $dsn = sprintf(
                'mysql:host=%s;port=%s;dbname=%s;charset=%s',
                $db['host'],
                $db['port'],
                $db['dbname'],
                $db['charset']
            );

            try {
                self::$database = new PDO($dsn, $db['username'], $db['password'], [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false
                ]);
            } catch (PDOException $e) {
                die('Erreur DB : ' . $e->getMessage());
            }
        }

        return self::$database;
    }

    
    public static function getLogger(string $channel): LoggerInterface
    {
        if (!isset(self::$loggers[$channel])) {
            $logDir = dirname(__DIR__, 3) . '/var/log';

            if (!is_dir($logDir)) {
                mkdir($logDir, 0777, true);
            }

            if ($channel === 'security') {
                // Créez d'abord le logger Monolog
                $monologLogger = new Logger($channel);
                $monologLogger->pushHandler(
                    new StreamHandler($logDir . '/' . $channel . '.log', Level::Debug) // ← Utilisez Level::Debug
                );
                
                // Retournez votre SecurityLogger
                self::$loggers[$channel] = new SecurityLogger($monologLogger, $logDir);
            } else {
                // Pour les autres channels, retournez Monolog standard
                $logger = new Logger($channel);
                $logger->pushHandler(
                    new StreamHandler($logDir . '/' . $channel . '.log', Level::Debug) // ← Utilisez Level::Debug
                );
                self::$loggers[$channel] = $logger;
            }
        }

        return self::$loggers[$channel];
    }


    public static function get(string $key, mixed $default = null): mixed
    {
        $value = self::$config;
        foreach (explode('.', $key) as $segment) {
            if (!isset($value[$segment])) {
                return $default;
            }
            $value = $value[$segment];
        }
        return $value;
    }

    public static function generateCsrfToken(): string
    {
        $_SESSION['csrf_tokens'] ??= [];

        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_tokens'][$token] = time();

        return $token;
    }

    public static function verifyCsrfToken(string $token): bool
    {
        if (!isset($_SESSION['csrf_tokens'][$token])) {
            return false;
        }

        unset($_SESSION['csrf_tokens'][$token]);
        return true;
    }

    /**
     * Alias pour verifyCsrfToken (utilisé par login.php, inscription.php, etc.)
     */
    public static function validateCsrfToken(string $token): bool
    {
        return self::verifyCsrfToken($token);
    }
}
