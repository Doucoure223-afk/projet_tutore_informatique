<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
    
    // Générer un nouvel ID de session pour la sécurité
    session_regenerate_id(true);
    
    // Initialiser des variables de session de sécurité
    $_SESSION['login_attempts'] = $_SESSION['login_attempts'] ?? 0;
    $_SESSION['last_attempt_time'] = $_SESSION['last_attempt_time'] ?? 0;
}

require_once __DIR__ . '/../vendor/autoload.php';
use Slim\Psr7\Factory\ServerRequestFactory;
use App\Infrastructure\ApplicationConfig;
use App\Security\Detector\SqlInjectionDetector;
use App\Security\Logger\SecurityLoggerInterface;
use App\Security\AI\ThreatIntelligenceEngine;
use App\Security\AI\FlaskAiClient;
use App\Security\Response\SecurityResponseFactory;
use App\Security\RateLimiter;
use App\Security\IpAccessControl;
use App\Security\SecureDataGateway;

// Initialisation
ApplicationConfig::initialize(__DIR__ . '/..');
$db = ApplicationConfig::getDatabase();
$logger = ApplicationConfig::getLogger('security');
$rateLimiter = new RateLimiter($db);
$ipAccessControl = new IpAccessControl($db);
$detector = new SqlInjectionDetector($logger);
$aiEngine = new ThreatIntelligenceEngine();
$flaskAiUrl = ApplicationConfig::get('ai.flask_url', 'http://127.0.0.1:5000');
$flaskAiClient = new FlaskAiClient($flaskAiUrl, $logger);
$responseFactory = new SecurityResponseFactory();
$secureDataGateway = new SecureDataGateway($db);

// Vérifier si en maintenance
if (ApplicationConfig::get('maintenance') === '1') {
    header('HTTP/1.1 503 Service Unavailable');
    exit('Maintenance en cours. Veuillez réessayer ultérieurement.');
}

// Liste noire / liste blanche : bloquer l'IP si nécessaire
$clientIpForAccess = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
if ($ipAccessControl->isBlocked($clientIpForAccess)) {
    showLoginForm('Accès refusé. Votre IP est bloquée ou non autorisée.');
    exit;
}

// Middleware de sécurité (API Flask en priorité, fallback moteur PHP)
$securityResult = processSecurityMiddleware($detector, $aiEngine, $flaskAiClient, $logger);

if ($securityResult->shouldBlock) {
    $threat = $securityResult->threatInfo;
    $attackType = $threat['type'] ?? 'SQL_INJECTION';
    $param = $threat['parameter'] ?? '';
    $payload = ($param !== '' && isset($_POST[$param])) ? (string) $_POST[$param] : '(requête bloquée)';
    $context = $threat;

    SecurityResponseFactory::createBlockedResponse($attackType, $payload, $context);
}

// Traitement du formulaire
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $keyHash = hash('sha256', $clientIp);

    if (!$rateLimiter->isAllowed($keyHash, 'login', RateLimiter::loginWindowSeconds(), RateLimiter::loginMaxAttempts())) {
        $remaining = $rateLimiter->getRemainingSeconds($keyHash, 'login', RateLimiter::loginWindowSeconds());
        $minutes = max(1, (int) ceil($remaining / 60));
        showLoginForm("Trop de tentatives. Réessayez dans {$minutes} minute(s).");
        exit;
    }

    if (!ApplicationConfig::validateCsrfToken($_POST['_token'] ?? '')) {
        handleSecurityViolation('CSRF_TOKEN_INVALID');
    }

    $credentials = validateAndSanitizeCredentials($_POST);

    if ($credentials === null) {
        showLoginForm('Identifiants invalides');
        exit;
    }

    // Flux diagramme : requête sécurisée → DB → filtrage → données nettoyées (via SecureDataGateway)
    $user = $secureDataGateway->authenticateAndGetUser($credentials['username'], $credentials['password']);

    if ($user === null) {
        $rateLimiter->recordAttempt($keyHash, 'login', RateLimiter::loginWindowSeconds());
        $logger->warning('LOGIN_FAILED', [
            'username' => $credentials['username_hash'],
            'ip' => $clientIp
        ]);

        showLoginForm('Identifiants incorrects');
        exit;
    }

    // Connexion réussie (données nettoyées reçues du gateway)
    createSecureSession($user);
    $logger->info('LOGIN_SUCCESS', [
        'user_id' => $user['id'],
        'ip' => $_SERVER['REMOTE_ADDR']
    ]);
    
    // Redirection vers le dashboard (point d'entrée public)
    $baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
    header('Location: ' . $baseUrl . '/dashboard.php', true, 303);
    exit;
}

// Affichage du formulaire (message après redirection CSRF si besoin)
$getError = $_GET['error'] ?? '';
$formError = ($getError === 'session_expired') ? 'Session expirée ou formulaire déjà envoyé. Veuillez vous reconnecter.' : '';
showLoginForm($formError);

// ==================== FONCTIONS ====================

function processSecurityMiddleware(
    SqlInjectionDetector $detector,
    ThreatIntelligenceEngine $aiEngine,
    FlaskAiClient $flaskAiClient,
    SecurityLoggerInterface $logger
): SecurityMiddlewareResult
{
    $requestData = array_merge($_GET, $_POST);
    $threatInfo = [];
    
    // Récupérer l'ID de session une seule fois
    $sessionId = session_id() ?: null;
    
    foreach ($requestData as $param => $value) {
        if (!is_string($value)) continue;
        
        $analysis = $detector->analyze($value, $param, 'login');
        
        if ($analysis->shouldBlock) {
            $logger->logSqlInjection(
                $_SERVER['REMOTE_ADDR'],
                $value,
                $analysis->score,
                $analysis->detectedPatterns,
                'BLOCKED',
                $param,
                'login'
            );
            
            return new SecurityMiddlewareResult(true, [
                'type' => 'SQL_INJECTION',
                'score' => $analysis->score,
                'parameter' => $param,
                'risk_level' => $analysis->riskLevel
            ]);
        }
        
        if ($analysis->needsAiAnalysis) {
            $context = [
                'type' => 'login',
                'parameter' => $param,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            ];
            $aiResult = null;
            $flaskResult = $flaskAiClient->analyze($value, $context, $sessionId);
            if ($flaskResult !== null) {
                $aiResult = (object)[
                    'riskScore' => $flaskResult['risk'],
                    'confidence' => $flaskResult['confidence'],
                    'threatType' => $flaskResult['type'],
                    'recommendations' => [],
                    'risk_factors' => $flaskResult['risk_factors'] ?? [],
                ];
            }
            if ($aiResult === null) {
                $aiResult = $aiEngine->analyzeThreat($value, $context, $sessionId);
            }
            // Bloquer uniquement pour des risques élevés (95+ %), sinon on laisse
            // l’utilisateur poursuivre tout en enregistrant l’analyse.
            if ($aiResult->riskScore > 0.95) {
                $logger->logSqlInjection(
                    $_SERVER['REMOTE_ADDR'],
                    $value,
                    (int)($aiResult->riskScore * 100),
                    [],
                    'BLOCKED_BY_AI',
                    $param,
                    'login'
                );
                return new SecurityMiddlewareResult(true, [
                    'type' => 'AI_DETECTED_THREAT',
                    'risk_score' => $aiResult->riskScore,
                    'confidence' => $aiResult->confidence,
                    'threat_type' => $aiResult->threatType,
                    'recommendations' => $aiResult->recommendations ?? [],
                    'risk_factors' => $aiResult->risk_factors ?? [],
                ]);
            }
        }
    }
    
    return new SecurityMiddlewareResult(false, []);
}

function validateAndSanitizeCredentials(array $post): ?array
{
    $username = trim($post['username'] ?? '');
    $password = $post['password'] ?? '';
    
    // Validation stricte
    if (empty($username) || empty($password)) {
        return null;
    }
    
    if (strlen($username) > 50 || strlen($password) > 100) {
        return null;
    }
    
    if (!preg_match('/^[a-zA-Z0-9_@.\-]{3,50}$/', $username)) {
        return null;
    }
    
    // Sanitisation
    $username = htmlspecialchars($username, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    
    // Hash pour le logging (ne pas logger le mot de passe)
    $usernameHash = hash('sha256', $username . $_SERVER['REMOTE_ADDR']);
    
    return [
        'username' => $username,
        'username_hash' => $usernameHash,
        'password' => $password
    ];
}

function createSecureSession(array $user): void
{
    // Régénérer l'ID de session
    session_regenerate_id(true);
    
    $_SESSION['authenticated'] = true;
    $_SESSION['user_id'] = (int)$user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['role'] = $user['role'];
    $_SESSION['login_time'] = time();
    $_SESSION['session_id'] = bin2hex(random_bytes(32));
    
    // Cookie sécurisé
    setcookie(
        'remember_token',
        bin2hex(random_bytes(32)),
        [
            'expires' => time() + 86400 * 30,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]
    );
}

function showLoginForm(string $error = ''): void
{
    $csrfToken = ApplicationConfig::generateCsrfToken();
    $errorHtml = '';
    $baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
    $aboutUrl = htmlspecialchars($baseUrl ? $baseUrl . '/a-propos.php' : 'a-propos.php', ENT_QUOTES, 'UTF-8');

    if (!empty($error)) {
        $errorHtml = '<div class="error-message" role="alert" aria-live="assertive">
            <i class="fas fa-exclamation-circle" aria-hidden="true"></i> '
            . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') .
            '</div>';
    }

    echo <<<HTML
    <!DOCTYPE html>
    <html lang="fr" data-theme="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Connexion Sécurisée • 2026</title>
        <script>(function(){var t=localStorage.getItem('theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t);})();</script>
        <link href="https://cdn.jsdelivr.net/npm/@shoelace-style/shoelace@2.0.0-beta.83/dist/themes/dark.css" rel="stylesheet">
        <script type="module" src="https://cdn.jsdelivr.net/npm/@shoelace-style/shoelace@2.0.0-beta.83/dist/shoelace.js"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root, [data-theme="dark"] {
                --login-bg: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                --login-card-bg: rgba(255, 255, 255, 0.1);
                --login-card-border: rgba(255, 255, 255, 0.2);
                --login-title: linear-gradient(to right, #fff, #a5b4fc);
                --login-text: #cbd5e1;
                --login-input-bg: rgba(255, 255, 255, 0.1);
                --login-input-border: rgba(255, 255, 255, 0.2);
                --login-input-color: #fff;
                --login-footer-border: rgba(255, 255, 255, 0.1);
                --login-footer-color: #94a3b8;
            }
            [data-theme="light"] {
                --login-bg: linear-gradient(135deg, #c7d2fe 0%, #e0e7ff 50%, #ddd6fe 100%);
                --login-card-bg: rgba(255, 255, 255, 0.95);
                --login-card-border: rgba(100, 116, 139, 0.3);
                --login-title: linear-gradient(to right, #3730a3, #5b21b6);
                --login-text: #334155;
                --login-input-bg: #f8fafc;
                --login-input-border: #cbd5e1;
                --login-input-color: #0f172a;
                --login-footer-border: #e2e8f0;
                --login-footer-color: #64748b;
            }
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: var(--login-bg);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .login-card {
                position: relative;
                background: var(--login-card-bg);
                backdrop-filter: blur(20px);
                border-radius: 24px;
                padding: 48px;
                width: 100%;
                max-width: 440px;
                border: 1px solid var(--login-card-border);
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.15);
            }
            .theme-toggle-login {
                position: absolute;
                top: 20px;
                right: 20px;
                width: 44px;
                height: 44px;
                border-radius: 12px;
                border: 1px solid var(--login-card-border);
                background: var(--login-input-bg);
                color: var(--login-input-color);
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.2rem;
                transition: border-color 0.2s, background 0.2s;
            }
            .theme-toggle-login:hover {
                border-color: #818cf8;
                background: rgba(129, 140, 248, 0.2);
            }
            h1 {
                font-size: 2.5rem;
                font-weight: 800;
                margin-bottom: 8px;
                background: var(--login-title);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            .security-badge {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                background: rgba(16, 185, 129, 0.2);
                color: #10b981;
                padding: 6px 12px;
                border-radius: 20px;
                font-size: 0.875rem;
                font-weight: 600;
                margin-top: 12px;
            }
            .error-message {
                background: rgba(220, 38, 38, 0.2);
                border: 1px solid rgba(220, 38, 38, 0.4);
                color: #fca5a5;
                padding: 16px;
                border-radius: 12px;
                margin: 24px 0;
                display: flex;
                align-items: center;
                gap: 12px;
            }
            .form-group {
                margin-bottom: 24px;
            }
            label {
                display: block;
                margin-bottom: 8px;
                font-weight: 600;
                color: var(--login-text);
            }
            input {
                width: 100%;
                padding: 16px;
                background: var(--login-input-bg);
                border: 1px solid var(--login-input-border);
                border-radius: 12px;
                color: var(--login-input-color);
                font-size: 1rem;
                transition: all 0.3s;
            }
            input:focus {
                outline: none;
                border-color: #818cf8;
                box-shadow: 0 0 0 3px rgba(129, 140, 248, 0.3);
            }
            .btn-login {
                width: 100%;
                padding: 18px;
                background: linear-gradient(to right, #667eea, #764ba2);
                color: white;
                border: none;
                border-radius: 12px;
                font-size: 1.125rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
                margin-top: 8px;
            }
            .btn-login:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
            }
            .security-footer {
                margin-top: 32px;
                padding-top: 24px;
                border-top: 1px solid var(--login-footer-border);
                font-size: 0.875rem;
                color: var(--login-footer-color);
                text-align: center;
            }
            .security-footer-features { display: flex; justify-content: center; gap: 24px; margin-bottom: 12px; flex-wrap: wrap; }
            @media (max-width: 480px) {
                body { padding: 12px; }
                .login-card { padding: 28px 20px; border-radius: 16px; }
                .theme-toggle-login { top: 12px; right: 12px; width: 40px; height: 40px; font-size: 1rem; }
                h1 { font-size: 1.75rem; }
                .security-footer-features { flex-direction: column; gap: 8px; align-items: center; }
            }
        </style>
    </head>
    <body>
        <div class="protection-banner" style="position: fixed; top: 0; left: 0; right: 0; background: linear-gradient(90deg, #059669, #047857); color: #fff; padding: 10px; text-align: center; font-weight: 700; font-size: 0.9rem; z-index: 9999;">
            ✓ PROTÉGÉ — Détection SQL + IA • Requêtes préparées • Rate limiting
        </div>
        <div class="login-card" style="margin-top: 40px;">
            <button type="button" class="theme-toggle-login" id="themeToggleLogin" title="Changer de thème" aria-label="Changer de thème">
                <i class="fas fa-moon" id="themeIconLogin"></i>
            </button>
            <div style="text-align: center; margin-bottom: 40px;">
                <div style="width: 64px; height: 64px; margin: 0 auto 16px; background: rgba(255,255,255,0.12); border: 1px solid rgba(255,255,255,0.2); border-radius: 18px; display: flex; align-items: center; justify-content: center;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width: 36px; height: 36px; stroke: #a5b4fc;" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 2L4 6v6c0 5.5 3.8 10.7 8 12 4.2-1.3 8-6.5 8-12V6l-8-4z"/>
                    </svg>
                </div>
                <h1>Connexion</h1>
                <p style="color: var(--login-text); margin-bottom: 12px;">Système de sécurité 2026</p>
                <div class="security-badge">
                    <i class="fas fa-shield-alt"></i>
                    Protection IA active
                </div>
            </div>
            
                {$errorHtml}
            <form method="POST" action="" id="loginForm">
                <input type="hidden" name="_token" value="{$csrfToken}">
                
                <div class="form-group">
                    <label for="username">Nom d'utilisateur</label>
                    <input type="text" id="username" name="username" required 
                           placeholder="votre.nom@entreprise.com"
                           autocomplete="username"
                           aria-required="true">
                </div>
                
                <div class="form-group">
                    <label for="password">Mot de passe</label>
                    <input type="password" id="password" name="password" required 
                           placeholder="••••••••••"
                           autocomplete="current-password"
                           aria-required="true">
                </div>
                
                <button type="submit" class="btn-login" aria-label="Se connecter au compte">
                    <i class="fas fa-sign-in-alt" aria-hidden="true"></i> Se connecter
                </button>
            </form>
            
            <div class="security-footer">
                <div class="security-footer-features">
                    <div><i class="fas fa-lock"></i> Chiffrement AES-256</div>
                    <div><i class="fas fa-robot"></i> Détection IA</div>
                    <div><i class="fas fa-shield-alt"></i> Zero Trust</div>
                </div>
                <p>© 2026 - Sécurité de niveau entreprise &nbsp;·&nbsp; <a href="{$aboutUrl}" style="color: inherit; opacity: 0.9;">À propos</a></p>
            </div>
        </div>
        
        <script>
            document.getElementById('loginForm').addEventListener('submit', function(e) {
                // Validation côté client
                const password = document.getElementById('password').value;
                if (password.length < 8) {
                    e.preventDefault();
                    alert('Le mot de passe doit contenir au moins 8 caractères');
                    return;
                }
                
                // Ajouter un indicateur de chargement
                const btn = this.querySelector('.btn-login');
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Vérification...';
                btn.disabled = true;
            });
            
            // Thème clair / sombre (partagé avec dashboard)
            document.addEventListener('DOMContentLoaded', function() {
                var theme = document.documentElement.getAttribute('data-theme') || 'dark';
                var btn = document.getElementById('themeToggleLogin');
                var icon = document.getElementById('themeIconLogin');
                if (btn && icon) {
                    icon.className = theme === 'light' ? 'fas fa-sun' : 'fas fa-moon';
                    btn.addEventListener('click', function() {
                        var next = theme === 'light' ? 'dark' : 'light';
                        theme = next;
                        localStorage.setItem('theme', next);
                        document.documentElement.setAttribute('data-theme', next);
                        icon.className = next === 'light' ? 'fas fa-sun' : 'fas fa-moon';
                    });
                }
                var inputs = document.querySelectorAll('input[autocomplete]');
                inputs.forEach(function(input) {
                    input.setAttribute('autocomplete', Math.random().toString(36));
                });
            });
        </script>
    </body>
    </html>
HTML;
}

// Classes auxiliaires
class SecurityMiddlewareResult
{
    public function __construct(
        public readonly bool $shouldBlock,
        public readonly array $threatInfo
    ) {}
}

function handleSecurityViolation(string $type): never
{
    $logger = ApplicationConfig::getLogger('security');
    $logger->critical('SECURITY_VIOLATION', [
        'type' => $type,
        'ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null
    ]);

    if ($type === 'CSRF_TOKEN_INVALID') {
        $self = $_SERVER['SCRIPT_NAME'] ?? '/login.php';
        header('Location: ' . $self . '?error=session_expired', true, 303);
        exit;
    }

    http_response_code(403);
    exit('Violation de sécurité détectée.');
}