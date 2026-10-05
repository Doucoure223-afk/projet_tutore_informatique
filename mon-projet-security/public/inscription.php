<?php
declare(strict_types=1);

// Démarrer la session au tout début (après declare)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/../vendor/autoload.php';

use App\Infrastructure\ApplicationConfig;
use App\Security\Detector\SqlInjectionDetector;
use App\Security\Logger\SecurityLoggerInterface;
use App\Security\AI\ThreatIntelligenceEngine;
use App\Security\AI\FlaskAiClient;
use App\Security\Response\SecurityResponseFactory;
use App\Security\RateLimiter;

// Initialisation
ApplicationConfig::initialize(__DIR__ . '/..');
$db = ApplicationConfig::getDatabase();
$logger = ApplicationConfig::getLogger('security');
$rateLimiter = new RateLimiter($db);
$detector = new SqlInjectionDetector($logger);
$aiEngine = new ThreatIntelligenceEngine();
$flaskAiUrl = ApplicationConfig::get('ai.flask_url', 'http://127.0.0.1:5000');
$flaskAiClient = new FlaskAiClient($flaskAiUrl, $logger);

// Middleware de sécurité (détection SQL + IA comme login.php)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $securityResult = processRegistrationSecurityMiddleware($detector, $aiEngine, $flaskAiClient, $logger);
    if ($securityResult->shouldBlock) {
        $threat = $securityResult->threatInfo;
        $attackType = $threat['type'] ?? 'SQL_INJECTION';
        $param = $threat['parameter'] ?? '';
        $payload = ($param !== '' && isset($_POST[$param])) ? (string) $_POST[$param] : '(requête bloquée)';
        SecurityResponseFactory::createBlockedResponse($attackType, $payload, $threat);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $keyHash = hash('sha256', $clientIp);

    if (!$rateLimiter->isAllowed($keyHash, 'registration', RateLimiter::registrationWindowSeconds(), RateLimiter::registrationMaxAttempts())) {
        $remaining = $rateLimiter->getRemainingSeconds($keyHash, 'registration', RateLimiter::registrationWindowSeconds());
        $hours = max(1, (int) ceil($remaining / 3600));
        showRegistrationForm("Trop de tentatives d'inscription. Réessayez dans {$hours} heure(s).");
        exit;
    }

    $rateLimiter->recordAttempt($keyHash, 'registration', RateLimiter::registrationWindowSeconds());

    if (!ApplicationConfig::validateCsrfToken($_POST['_token'] ?? '')) {
        showRegistrationForm('Session expirée. Veuillez réessayer.');
        exit;
    }
    $securityCheck = validateRegistrationInput($_POST, $detector);
    
    if (!$securityCheck['valid']) {
        showRegistrationForm($securityCheck['error']);
        exit;
    }
    
    $userData = $securityCheck['data'];
    
    // Vérifier l'unicité
    if (userExists($db, $userData['email'], $userData['username'])) {
        showRegistrationForm('Cet utilisateur existe déjà');
        exit;
    }
    
    // Créer l'utilisateur
    $userId = createUser($db, $userData);
    
    if ($userId) {
        // Log de succès
        $logger->info('USER_REGISTERED', [
            'user_id' => $userId,
            'ip' => $_SERVER['REMOTE_ADDR']
        ]);
        
        // Redirection vers login
        $baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
        header('Location: ' . $baseUrl . '/login.php?registered=1', true, 303);
        exit;
    }
    
    showRegistrationForm('Erreur lors de la création du compte');
    exit;
}

// Afficher le formulaire
showRegistrationForm();

// ==================== FONCTIONS ====================

function processRegistrationSecurityMiddleware(
    SqlInjectionDetector $detector,
    ThreatIntelligenceEngine $aiEngine,
    FlaskAiClient $flaskAiClient,
    SecurityLoggerInterface $logger
): SecurityMiddlewareResult {
    $requestData = array_merge($_GET, $_POST);
    $sessionId = session_id() ?: null;

    foreach ($requestData as $param => $value) {
        if (!is_string($value)) continue;
        if (in_array($param, ['_token', 'terms', 'privacy', 'password_confirm'], true)) continue;

        $analysis = $detector->analyze($value, $param, 'registration');

        if ($analysis->shouldBlock) {
            $logger->logSqlInjection(
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $value,
                $analysis->score,
                $analysis->detectedPatterns ?? [],
                'BLOCKED',
                $param,
                'registration'
            );
            return new SecurityMiddlewareResult(true, [
                'type' => 'SQL_INJECTION',
                'score' => $analysis->score,
                'parameter' => $param,
                'risk_level' => $analysis->riskLevel ?? 'high',
            ]);
        }

        if ($analysis->needsAiAnalysis) {
            $context = [
                'type' => 'registration',
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
            if ($aiResult->riskScore > 0.75) {
                $logger->logSqlInjection(
                    $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                    $value,
                    (int)($aiResult->riskScore * 100),
                    [],
                    'BLOCKED_BY_AI',
                    $param,
                    'registration'
                );
                return new SecurityMiddlewareResult(true, [
                    'type' => 'AI_DETECTED_THREAT',
                    'risk_score' => $aiResult->riskScore,
                    'confidence' => $aiResult->confidence,
                    'threat_type' => $aiResult->threatType,
                    'parameter' => $param,
                    'recommendations' => $aiResult->recommendations ?? [],
                    'risk_factors' => $aiResult->risk_factors ?? [],
                ]);
            }
        }
    }

    return new SecurityMiddlewareResult(false, []);
}

class SecurityMiddlewareResult
{
    public function __construct(
        public readonly bool $shouldBlock,
        public readonly array $threatInfo
    ) {}
}

function validateRegistrationInput(array $post, SqlInjectionDetector $detector): array
{
    $required = ['username', 'email', 'password', 'password_confirm'];
    
    foreach ($required as $field) {
        if (empty(trim($post[$field] ?? ''))) {
            return ['valid' => false, 'error' => "Le champ {$field} est requis"];
        }
    }
    
    if (empty($post['terms']) || empty($post['privacy'])) {
        return ['valid' => false, 'error' => 'Vous devez accepter les conditions et la politique de confidentialité'];
    }
    
    // Validation des données
    $username = trim($post['username']);
    $email = filter_var(trim($post['email']), FILTER_VALIDATE_EMAIL);
    $password = $post['password'];
    $passwordConfirm = $post['password_confirm'];
    
    if (!$email) {
        return ['valid' => false, 'error' => 'Adresse email invalide'];
    }
    
    if (strlen($username) < 3 || strlen($username) > 30) {
        return ['valid' => false, 'error' => 'Le nom d\'utilisateur doit faire entre 3 et 30 caractères'];
    }
    
    if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $username)) {
        return ['valid' => false, 'error' => 'Le nom d\'utilisateur contient des caractères invalides'];
    }
    
    if ($password !== $passwordConfirm) {
        return ['valid' => false, 'error' => 'Les mots de passe ne correspondent pas'];
    }
    
    if (strlen($password) < 12) {
        return ['valid' => false, 'error' => 'Le mot de passe doit contenir au moins 12 caractères'];
    }
    
    if (!preg_match('/[A-Z]/', $password) || 
        !preg_match('/[a-z]/', $password) || 
        !preg_match('/[0-9]/', $password) ||
        !preg_match('/[^A-Za-z0-9]/', $password)) {
        return ['valid' => false, 'error' => 'Le mot de passe doit contenir des majuscules, minuscules, chiffres et caractères spéciaux'];
    }
    
    // Détection de menaces (paramètre = nom du champ pour les logs)
    $inputsToCheck = ['username' => $username, 'email' => $email, 'password' => $password];
    foreach ($inputsToCheck as $paramName => $input) {
        $analysis = $detector->analyze($input, $paramName, 'registration');
        
        if ($analysis->shouldBlock) {
            /** @var \App\Security\Logger\SecurityLoggerInterface $securityLogger */
            $securityLogger = ApplicationConfig::getLogger('security');
            $securityLogger->logSqlInjection(
                    $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                    $input,
                    $analysis->score,
                    $analysis->detectedPatterns ?? [],
                    'BLOCKED',
                    $paramName,
                    'registration'
                );
            
            return ['valid' => false, 'error' => 'Entrée bloquée par notre système de sécurité'];
        }
    }
    
    return [
        'valid' => true,
        'data' => [
            'username' => htmlspecialchars($username, ENT_QUOTES, 'UTF-8'),
            'email' => $email,
            'password' => $password,
            'role' => 'user'
        ]
    ];
}

function userExists(PDO $db, string $email, string $username): bool
{
    $query = "SELECT COUNT(*) FROM users 
              WHERE email = :email OR username = :username 
              AND deleted_at IS NULL";
    
    $stmt = $db->prepare($query);
    $stmt->execute([
        ':email' => $email,
        ':username' => $username
    ]);
    
    return $stmt->fetchColumn() > 0;
}

function createUser(PDO $db, array $data): ?int
{
    $passwordHash = password_hash($data['password'], PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost' => 4,
        'threads' => 2
    ]);
    
    $verificationToken = bin2hex(random_bytes(32));
    
    // Insertion utilisateur : essai avec colonnes étendues (is_active, is_locked), sinon schéma minimal
    $queries = [
        "INSERT INTO users (
            username, email, password_hash, role,
            verification_token, email_verified_at,
            created_at, updated_at,
            login_attempts, mfa_enabled,
            is_active, is_locked
        ) VALUES (
            :username, :email, :password_hash, :role,
            :verification_token, NULL,
            NOW(), NOW(),
            0, 0,
            1, 0
        )",
        "INSERT INTO users (
            username, email, password_hash, role,
            verification_token, email_verified_at,
            created_at, updated_at,
            login_attempts, mfa_enabled
        ) VALUES (
            :username, :email, :password_hash, :role,
            :verification_token, NULL,
            NOW(), NOW(),
            0, 0
        )",
        "INSERT INTO users (
            username, email, password_hash, role,
            verification_token, email_verified_at,
            created_at, updated_at
        ) VALUES (
            :username, :email, :password_hash, :role,
            :verification_token, NULL,
            NOW(), NOW()
        )"
    ];
    
    $params = [
        ':username' => $data['username'],
        ':email' => $data['email'],
        ':password_hash' => $passwordHash,
        ':role' => $data['role'],
        ':verification_token' => $verificationToken
    ];
    
    $userId = null;
    foreach ($queries as $query) {
        try {
            $db->beginTransaction();
            $stmt = $db->prepare($query);
            $stmt->execute($params);
            $userId = (int) $db->lastInsertId();
            $db->commit();
            break;
        } catch (PDOException $e) {
            $db->rollBack();
            if (strpos($e->getMessage(), 'Unknown column') !== false) {
                continue;
            }
            ApplicationConfig::getLogger('database')->error('USER_CREATION_FAILED', [
                'error' => $e->getMessage(),
                'email' => $data['email']
            ]);
            return null;
        }
    }
    
    if ($userId === null) {
        ApplicationConfig::getLogger('database')->error('USER_CREATION_FAILED', [
            'message' => 'Aucune variante d\'INSERT ne correspond à la table users',
            'email' => $data['email']
        ]);
        return null;
    }
    
    // Profil utilisateur (optionnel : si la table n'existe pas, l'utilisateur est quand même créé)
    try {
        $profileStmt = $db->prepare("INSERT INTO user_profiles (user_id, created_at) VALUES (:user_id, NOW())");
        $profileStmt->execute([':user_id' => $userId]);
    } catch (PDOException $e) {
        ApplicationConfig::getLogger('database')->warning('USER_PROFILE_SKIPPED', [
            'user_id' => $userId,
            'error' => $e->getMessage()
        ]);
    }
    
    // Email de vérification (optionnel : ne pas bloquer la création)
    try {
        sendVerificationEmail($data['email'], $verificationToken);
    } catch (\Throwable $e) {
        ApplicationConfig::getLogger('mail')->warning('VERIFICATION_EMAIL_SKIP', [
            'email' => $data['email'],
            'error' => $e->getMessage()
        ]);
    }
    
    return $userId;
}

function sendVerificationEmail(string $email, string $token): bool
{
    try {
        // Récupérer la configuration
        $appName = ApplicationConfig::get('app.name') ?? 'Notre Application';
        $appUrl = ApplicationConfig::get('app.url') ?? 'http://localhost:8000';
        $fromEmail = ApplicationConfig::get('mail.from') ?? 'noreply@example.com';
        $fromName = ApplicationConfig::get('mail.from_name') ?? $appName;
        
        // Construire le lien de vérification
        $verificationLink = $appUrl . "/verify-email?token=" . urlencode($token);
        
        // Sujet de l'email
        $subject = "[" . $appName . "] Vérification de votre adresse email";
        
        // Corps de l'email en HTML
        $htmlMessage = <<<HTML
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vérification d'email</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                  padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .header h1 { color: white; margin: 0; font-size: 24px; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; background: #667eea; color: white; 
                  padding: 12px 24px; text-decoration: none; border-radius: 5px; 
                  font-weight: bold; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
        .code { background: #eee; padding: 10px; border-radius: 5px; font-family: monospace; 
                word-break: break-all; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{$appName}</h1>
        </div>
        <div class="content">
            <h2>Bonjour,</h2>
            <p>Merci de vous être inscrit sur <strong>{$appName}</strong> !</p>
            <p>Pour compléter votre inscription et activer votre compte, 
               veuillez vérifier votre adresse email en cliquant sur le bouton ci-dessous :</p>
            
            <div style="text-align: center;">
                <a href="{$verificationLink}" class="button">
                    Vérifier mon adresse email
                </a>
            </div>
            
            <p>Si le bouton ne fonctionne pas, vous pouvez copier-coller ce lien dans votre navigateur :</p>
            <div class="code">{$verificationLink}</div>
            
            <p><strong>Important :</strong> Ce lien de vérification expirera dans 24 heures.</p>
            
            <p>Si vous n'avez pas créé de compte sur {$appName}, vous pouvez ignorer cet email.</p>
            
            <p>Cordialement,<br>L'équipe {$appName}</p>
        </div>
        <div class="footer">
            <p>Cet email a été envoyé automatiquement, merci de ne pas y répondre.</p>
            <p>&copy; " . date('Y') . " {$appName}. Tous droits réservés.</p>
        </div>
    </div>
</body>
</html>
HTML;

        // En-têtes pour l'email HTML
        $headers = [
            'MIME-Version: 1.0',
            'Content-Type: text/html; charset=UTF-8',
            'From: "' . $fromName . '" <' . $fromEmail . '>',
            'Reply-To: ' . $fromEmail,
            'X-Mailer: PHP/' . phpversion(),
            'X-Priority: 1',
            'X-MSMail-Priority: High'
        ];

        // Envoyer l'email
        $sent = mail($email, $subject, $htmlMessage, implode("\r\n", $headers));
        
        // Logger le résultat
        $logger = ApplicationConfig::getLogger('mail');
        if ($sent) {
            $logger->info('VERIFICATION_EMAIL_SENT', ['email' => $email]);
        } else {
            $logger->error('VERIFICATION_EMAIL_FAILED', ['email' => $email]);
        }
        
        return $sent;
        
    } catch (\Exception $e) {
        // Logger l'erreur
        ApplicationConfig::getLogger('mail')->error('EMAIL_EXCEPTION', [
            'email' => $email,
            'error' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ]);
        return false;
    }
}

function showRegistrationForm(string $error = ''): void
{
    $csrfToken = ApplicationConfig::generateCsrfToken();
    $baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
    $loginUrl = $baseUrl . '/login.php';
    $errorHtml = '';

    if (!empty($error)) {
        $errorHtml = '<div class="form-error" role="alert" aria-live="polite">
            <span class="form-error-icon" aria-hidden="true">!</span>
            <span>' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . '</span>
        </div>';
    }

    echo <<<HTML
<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inscription • SHIELD CORE 2026</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --sc-bg: #060b12;
            --sc-surface: rgba(15, 23, 42, 0.92);
            --sc-border: rgba(148, 163, 184, 0.15);
            --sc-text: #f1f5f9;
            --sc-muted: #94a3b8;
            --sc-primary: #0ea5e9;
            --sc-primary-glow: rgba(14, 165, 233, 0.35);
            --sc-success: #10b981;
            --sc-danger: #ef4444;
            --sc-radius: 14px;
            --sc-font: 'Space Grotesk', system-ui, sans-serif;
            --sc-mono: 'JetBrains Mono', monospace;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: var(--sc-font);
            background: var(--sc-bg);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: clamp(16px, 4vw, 28px);
        }
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background: radial-gradient(ellipse 80% 50% at 50% -20%, var(--sc-primary-glow), transparent 50%),
                        linear-gradient(180deg, var(--sc-bg) 0%, #0c1222 100%);
            pointer-events: none;
            z-index: 0;
        }
        .register-wrap {
            position: relative;
            z-index: 1;
            width: 100%;
            max-width: min(480px, 96vw);
            animation: cardIn 0.5s cubic-bezier(0.22, 1, 0.36, 1);
        }
        @keyframes cardIn {
            from { opacity: 0; transform: translateY(16px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .register-card {
            background: var(--sc-surface);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--sc-border);
            border-radius: 24px;
            padding: clamp(28px, 5vw, 44px);
            box-shadow: 0 0 0 1px rgba(14, 165, 233, 0.1), 0 24px 48px -12px rgba(0, 0, 0, 0.5);
        }
        .register-header {
            text-align: center;
            margin-bottom: 32px;
        }
        .register-header .icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 20px;
            background: linear-gradient(135deg, rgba(14, 165, 233, 0.2), rgba(139, 92, 246, 0.2));
            border: 1px solid var(--sc-border);
            border-radius: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .register-header .icon svg {
            width: 36px;
            height: 36px;
            stroke: var(--sc-primary);
        }
        .register-header h1 {
            font-size: clamp(1.5rem, 4vw, 2rem);
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 8px;
            background: linear-gradient(135deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .register-header p { color: var(--sc-muted); font-size: 0.9375rem; }
        .form-error {
            display: flex;
            align-items: center;
            gap: 12px;
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
            padding: 14px 18px;
            border-radius: var(--sc-radius);
            margin-bottom: 24px;
            font-size: 0.9375rem;
        }
        .form-error-icon {
            width: 24px;
            height: 24px;
            background: var(--sc-danger);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 0.875rem;
            flex-shrink: 0;
        }
        .form-group { margin-bottom: 22px; }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--sc-text);
            font-size: 0.9375rem;
        }
        .form-group input,
        .form-group select {
            width: 100%;
            padding: clamp(14px, 2.5vw, 16px) 16px;
            min-height: 48px;
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid var(--sc-border);
            border-radius: var(--sc-radius);
            color: var(--sc-text);
            font-family: var(--sc-font);
            font-size: 1rem;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .form-group input::placeholder,
        .form-group select option { color: var(--sc-muted); }
        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: var(--sc-primary);
            box-shadow: 0 0 0 3px var(--sc-primary-glow);
        }
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .password-strength {
            margin-top: 10px;
            height: 6px;
            border-radius: 3px;
            background: rgba(255, 255, 255, 0.08);
            overflow: hidden;
        }
        .strength-meter {
            height: 100%;
            width: 0%;
            border-radius: 3px;
            transition: width 0.35s ease, background-color 0.35s ease;
        }
        .requirements {
            margin-top: 14px;
            padding: 16px 18px;
            background: rgba(0, 0, 0, 0.2);
            border-radius: var(--sc-radius);
            border: 1px solid var(--sc-border);
            font-size: 0.875rem;
        }
        .requirement {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
            transition: color 0.2s;
        }
        .requirement:last-child { margin-bottom: 0; }
        .requirement::before {
            content: '';
            width: 18px;
            height: 18px;
            border-radius: 50%;
            border: 2px solid currentColor;
            flex-shrink: 0;
        }
        .requirement.valid { color: var(--sc-success); }
        .requirement.valid::before {
            content: '✓';
            border: none;
            background: var(--sc-success);
            color: #fff;
            font-size: 0.7rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .requirement.invalid { color: #f87171; }
        .match-error {
            margin-top: 8px;
            font-size: 0.875rem;
            color: #f87171;
            display: none;
        }
        .match-error.visible { display: block; }
        .requirements-alert {
            display: none;
            margin-top: 10px;
            padding: 12px 16px;
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
            border-radius: var(--sc-radius);
            font-size: 0.875rem;
        }
        .requirements-alert.visible { display: block; }
        .legal-block {
            background: rgba(0, 0, 0, 0.25);
            border: 1px solid var(--sc-border);
            border-radius: var(--sc-radius);
            padding: 20px;
            margin-bottom: 28px;
        }
        .legal-row {
            display: flex;
            align-items: flex-start;
            gap: 14px;
            margin-bottom: 14px;
        }
        .legal-row:last-child { margin-bottom: 0; }
        .legal-row input[type="checkbox"] {
            width: 22px;
            height: 22px;
            min-width: 22px;
            min-height: 22px;
            margin-top: 2px;
            accent-color: var(--sc-primary);
            cursor: pointer;
        }
        .legal-row label {
            color: var(--sc-muted);
            font-size: 0.9375rem;
            line-height: 1.5;
            cursor: pointer;
        }
        .legal-row a {
            color: var(--sc-primary);
            text-decoration: none;
        }
        .legal-row a:hover { text-decoration: underline; }
        .btn-submit {
            width: 100%;
            min-height: 52px;
            padding: 16px 24px;
            background: linear-gradient(135deg, var(--sc-primary) 0%, #0284c7 100%);
            color: #fff;
            border: none;
            border-radius: var(--sc-radius);
            font-family: var(--sc-font);
            font-size: 1.0625rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            box-shadow: 0 4px 16px var(--sc-primary-glow);
        }
        .btn-submit:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px var(--sc-primary-glow);
        }
        .btn-submit:focus-visible { outline: 2px solid var(--sc-primary); outline-offset: 2px; }
        .btn-submit:disabled { opacity: 0.8; cursor: not-allowed; }
        .btn-submit .spinner {
            width: 22px;
            height: 22px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .footer-link {
            margin-top: 28px;
            text-align: center;
        }
        .footer-link p { color: var(--sc-muted); font-size: 0.9375rem; }
        .footer-link a {
            color: var(--sc-primary);
            text-decoration: none;
            font-weight: 600;
        }
        .footer-link a:hover { text-decoration: underline; }
        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0,0,0,0);
            white-space: nowrap;
            border: 0;
        }
        @media (max-width: 520px) {
            .form-row { grid-template-columns: 1fr; }
            .register-card { padding: 28px 22px; }
        }
    </style>
</head>
<body>
    <div class="register-wrap">
        <div class="register-card">
            <header class="register-header">
                <div class="icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 2L4 6v6c0 5.5 3.8 10.7 8 12 4.2-1.3 8-6.5 8-12V6l-8-4z"/>
                    </svg>
                </div>
                <h1>Créer un compte</h1>
                <p>Rejoignez notre plateforme sécurisée</p>
            </header>
        
            <form method="POST" action="" id="registerForm" novalidate>
                {$errorHtml}
                <input type="hidden" name="_token" value="{$csrfToken}">
                
                <div class="form-group">
                    <label for="username">Nom d'utilisateur</label>
                    <input type="text" id="username" name="username" required 
                           placeholder="john_doe" autocomplete="username"
                           minlength="3" maxlength="30">
                </div>
                
                <div class="form-group">
                    <label for="email">Adresse email</label>
                    <input type="email" id="email" name="email" required 
                           placeholder="vous@exemple.com" autocomplete="email">
                </div>
                
                <div class="form-group">
                    <label for="password">Mot de passe</label>
                    <input type="password" id="password" name="password" required 
                           placeholder="••••••••••" autocomplete="new-password"
                           minlength="12" aria-describedby="passwordRequirements"
                           oninput="checkPasswordStrength(this.value); var a=document.getElementById('requirementsAlert'); if(a) a.classList.remove('visible');">
                    <div class="password-strength">
                        <div class="strength-meter" id="strengthMeter"></div>
                    </div>
                    <div class="requirements" id="passwordRequirements" role="status" aria-live="polite">
                        <div class="requirement invalid" id="reqLength">12 caractères minimum</div>
                        <div class="requirement invalid" id="reqUpper">1 majuscule minimum</div>
                        <div class="requirement invalid" id="reqLower">1 minuscule minimum</div>
                        <div class="requirement invalid" id="reqNumber">1 chiffre minimum</div>
                        <div class="requirement invalid" id="reqSpecial">1 caractère spécial</div>
                        <div class="requirements-alert" id="requirementsAlert">Veuillez respecter tous les critères ci-dessus avant de continuer.</div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="passwordConfirm">Confirmer le mot de passe</label>
                    <input type="password" id="passwordConfirm" name="password_confirm" required 
                           placeholder="••••••••••" autocomplete="new-password"
                           oninput="checkPasswordMatch()" aria-describedby="passwordMatchError">
                    <div class="match-error" id="passwordMatchError" role="alert">Les mots de passe ne correspondent pas</div>
                </div>
                
                <div class="legal-block">
                    <div class="legal-row">
                        <input type="checkbox" id="terms" name="terms" required aria-required="true">
                        <label for="terms">J'accepte les <a href="terms.php" target="_blank" rel="noopener noreferrer">conditions d'utilisation</a></label>
                    </div>
                    <div class="legal-row">
                        <input type="checkbox" id="privacy" name="privacy" required aria-required="true">
                        <label for="privacy">J'accepte la <a href="politique-confidentialite.php" target="_blank" rel="noopener noreferrer">politique de confidentialité</a></label>
                    </div>
                </div>
                
                <button type="submit" class="btn-submit" id="submitBtn">
                    <span class="btn-text">Créer mon compte</span>
                </button>
            </form>
        
            <div class="footer-link">
                <p>Déjà un compte ? <a href="{$loginUrl}">Connectez-vous</a></p>
            </div>
        </div>
    </div>
    
    <script>
        function checkPasswordStrength(password) {
            var meter = document.getElementById('strengthMeter');
            var requirements = {
                length: password.length >= 12,
                upper: /[A-Z]/.test(password),
                lower: /[a-z]/.test(password),
                number: /[0-9]/.test(password),
                special: /[^A-Za-z0-9]/.test(password)
            };
            var ids = { length: 'Length', upper: 'Upper', lower: 'Lower', number: 'Number', special: 'Special' };
            for (var key in ids) {
                var el = document.getElementById('req' + ids[key]);
                if (el) {
                    el.classList.toggle('valid', requirements[key]);
                    el.classList.toggle('invalid', !requirements[key]);
                }
            }
            var score = Object.keys(requirements).filter(function(k) { return requirements[k]; }).length;
            var width = (score / 5) * 100;
            var color = score <= 2 ? '#ef4444' : score <= 4 ? '#f59e0b' : '#10b981';
            meter.style.width = width + '%';
            meter.style.backgroundColor = color;
        }
        function checkPasswordMatch() {
            var password = document.getElementById('password').value;
            var confirm = document.getElementById('passwordConfirm').value;
            var err = document.getElementById('passwordMatchError');
            err.classList.toggle('visible', confirm.length > 0 && password !== confirm);
        }
        document.addEventListener('DOMContentLoaded', function() {
            var form = document.getElementById('registerForm');
            if (!form) return;
            form.addEventListener('submit', function(e) {
                var password = document.getElementById('password');
                var confirmEl = document.getElementById('passwordConfirm');
                var matchError = document.getElementById('passwordMatchError');
                var passwordReq = document.getElementById('passwordRequirements');
                if (!password || !confirmEl) return;
                var pwd = password.value;
                var conf = confirmEl.value;
                if (pwd !== conf) {
                    e.preventDefault();
                    if (matchError) matchError.classList.add('visible');
                    confirmEl.focus();
                    return;
                }
                var reqs = [pwd.length >= 12, /[A-Z]/.test(pwd), /[a-z]/.test(pwd), /[0-9]/.test(pwd), /[^A-Za-z0-9]/.test(pwd)];
                var alertEl = document.getElementById('requirementsAlert');
                if (reqs.indexOf(false) !== -1) {
                    e.preventDefault();
                    if (alertEl) alertEl.classList.add('visible');
                    if (passwordReq) passwordReq.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    password.focus();
                    return;
                }
                if (alertEl) alertEl.classList.remove('visible');
                var btn = document.getElementById('submitBtn');
                if (btn) {
                    btn.disabled = true;
                    btn.innerHTML = '<span class="spinner"></span><span>Création en cours...</span>';
                }
            });
        });
    </script>
</body>
</html>
HTML;
}