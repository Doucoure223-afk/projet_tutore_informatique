<?php
// Démarrage sécurisé de session
if (session_status() === PHP_SESSION_NONE) {
    // Configuration sécurisée des sessions
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'] ?? '',
        'secure' => isset($_SERVER['HTTPS']),
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    session_start();
    
    // Protection contre la fixation de session
    if (empty($_SESSION['initiated'])) {
        session_regenerate_id(true);
        $_SESSION['initiated'] = true;
        $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'] ?? '';
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
    }
}

// Connexion MySQL vulnérable (pour démo)
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "projet_sqli_vulnerable";

// Connexion principale
$conn = mysqli_connect($servername, $username, $password, $dbname);

if (!$conn) {
    // En production, loguer sans afficher de détails
    error_log("Database connection failed");
    die("Erreur de connexion à la base de données");
}

// Connexion sécurisée pour les logs
$conn_logs = mysqli_connect($servername, $username, $password, $dbname);
if (!$conn_logs) {
    error_log("Logs database connection failed");
    // On utilise la connexion principale en fallback
    $conn_logs = $conn;
}

// Fonctions pour le système de sécurité
function getDatabaseConnection() {
    global $conn;
    return $conn;
}

function getLogsDatabaseConnection() {
    global $conn_logs;
    return $conn_logs;
}

// Protection CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function validate_csrf_token() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            header('HTTP/1.1 403 Forbidden');
            die("Erreur de sécurité CSRF");
        }
    }
}

// Fonction pour exécuter des requêtes vulnérables (démonstration)
function execute_query_vulnerable($sql) {
    global $conn;
    
    // Mode rapport d'erreurs
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    
    try {
        $result = mysqli_query($conn, $sql);
        
        if (!$result) {
            // Affichage contrôlé des erreurs (uniquement en développement)
            if (isset($_GET['debug']) && $_GET['debug'] == '1') {
                echo "<div style='background:#ffcccc;padding:10px;margin:10px;border:1px solid red;'>";
                echo "<strong>ERREUR SQL:</strong> " . mysqli_error($conn) . "<br>";
                echo "<strong>Requête:</strong> " . htmlspecialchars($sql);
                echo "</div>";
            }
            return false;
        }
        
        return $result;
    } catch (mysqli_sql_exception $e) {
        // Log en production, affichage limité en dev
        error_log("SQL Exception: " . $e->getMessage());
        
        if (isset($_GET['debug']) && $_GET['debug'] == '1') {
            echo "<div style='background:#ffcccc;padding:10px;margin:10px;border:1px solid red;'>";
            echo "<strong>EXCEPTION SQL:</strong> " . htmlspecialchars($e->getMessage()) . "<br>";
            echo "<strong>Requête:</strong> " . htmlspecialchars($sql);
            echo "</div>";
        }
        return false;
    }
}

// Fonction pour exécuter des requêtes sécurisées
function execute_query_secure($sql, $params = []) {
    global $conn;
    
    try {
        $stmt = mysqli_prepare($conn, $sql);
        if (!$stmt) {
            error_log("Prepare failed: " . mysqli_error($conn));
            return false;
        }
        
        if (!empty($params)) {
            $types = '';
            $bind_params = [];
            
            foreach ($params as $param) {
                if (is_int($param)) {
                    $types .= 'i';
                } elseif (is_double($param)) {
                    $types .= 'd';
                } else {
                    $types .= 's';
                }
                $bind_params[] = $param;
            }
            
            mysqli_stmt_bind_param($stmt, $types, ...$bind_params);
        }
        
        if (!mysqli_stmt_execute($stmt)) {
            error_log("Execute failed: " . mysqli_stmt_error($stmt));
            mysqli_stmt_close($stmt);
            return false;
        }
        
        $result = mysqli_stmt_get_result($stmt);
        mysqli_stmt_close($stmt);
        
        return $result;
    } catch (Exception $e) {
        error_log("Secure query exception: " . $e->getMessage());
        return false;
    }
}

// Configuration globale
define('APP_ENV', 'development'); // 'development' ou 'production'
define('MAX_UPLOAD_SIZE', 2 * 1024 * 1024); // 2MB
define('SESSION_TIMEOUT', 1800); // 30 minutes

// Fonction pour déterminer l'environnement
function is_development() {
    return APP_ENV === 'development';
}

// Fonction pour échapper les sorties
function escape_output($string) {
    return htmlspecialchars($string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}
?>