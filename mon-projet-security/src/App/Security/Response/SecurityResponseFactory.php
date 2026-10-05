<?php
declare(strict_types=1);

namespace App\Security\Response;

use App\Infrastructure\ApplicationConfig;
use App\Security\IpGeolocation;
use Ramsey\Uuid\Uuid;

/**
 * Factory de réponses de sécurité pour le middleware SQLi
 * Compatible avec l'architecture existante
 */
class SecurityResponseFactory
{
    public static function createBlockedResponse(
        string $attackType, 
        string $payload, 
        array $context = []
    ): void {
        http_response_code(403);
        
        // En-têtes de sécurité modernes
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: no-referrer');
        // CSP : autoriser reCAPTCHA (script + iframe) + polices Google
        header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' https://www.google.com https://www.gstatic.com; style-src \'self\' \'unsafe-inline\' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; frame-src https://www.google.com https://www.recaptcha.net; img-src \'self\' https://www.gstatic.com https://www.google.com');
        
        // Log de l'incident
        self::logIncident($attackType, $payload, $context);
        
        // Affichage de la page de blocage
        self::renderBlockedPage($attackType, $payload, $context);
        exit();
    }
    
    public static function createWarningResponse(
        string $warningType,
        string $message,
        array $context = []
    ): void {
        http_response_code(200); // 200 OK mais avec warning
        
        // En-tête de warning personnalisé
        header('X-Security-Warning: ' . $warningType);
        
        // Log du warning
        error_log("SECURITY_WARNING: $warningType - $message");
        
        // Le script continue normalement
    }
    
    private static function renderBlockedPage(
        string $attackType,
        string $payload,
        array $context
    ): void {
        $incidentId = strtoupper(bin2hex(random_bytes(8)));
        $timestamp = date('Y-m-d H:i:s');
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $riskLevel = $context['risk_level'] ?? 'CRITICAL';
        $score = (int) ($context['score'] ?? 0);
        // Blocage par l'IA : le contexte a risk_score (0-1) mais pas score → afficher un score dérivé
        if ($score === 0 && isset($context['risk_score'])) {
            $score = (int) round((float) $context['risk_score'] * 100);
        }
        $payloadSafe = htmlspecialchars(substr($payload, 0, 120), ENT_QUOTES, 'UTF-8');
        $userAgentShort = htmlspecialchars(substr($userAgent, 0, 60), ENT_QUOTES, 'UTF-8');
        $recaptchaSiteKey = trim((string) ApplicationConfig::get('recaptcha.site_key', ''));
        if ($recaptchaSiteKey === '') {
            $recaptchaSiteKey = trim((string) (getenv('RECAPTCHA_SITE_KEY') ?: ''));
        }
        $hasCaptcha = $recaptchaSiteKey !== '';
        ?>
<!-- recaptcha_key_loaded=<?php echo $hasCaptcha ? 'yes' : 'no'; ?> len=<?php echo strlen($recaptchaSiteKey); ?> -->
<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Requête bloquée • SHIELD CORE 2026</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-base: #060b12;
            --bg-surface: #0f172a;
            --bg-card: rgba(15, 23, 42, 0.92);
            --border: rgba(148, 163, 184, 0.12);
            --border-glow: rgba(14, 165, 233, 0.2);
            --text: #f1f5f9;
            --text-muted: #94a3b8;
            --primary: #0ea5e9;
            --primary-glow: rgba(14, 165, 233, 0.35);
            --danger: #ef4444;
            --danger-glow: rgba(239, 68, 68, 0.2);
            --danger-soft: rgba(239, 68, 68, 0.12);
            --success: #10b981;
            --success-soft: rgba(16, 185, 129, 0.15);
            --accent: #8b5cf6;
            --radius: 20px;
            --radius-sm: 12px;
            --font-sans: 'Space Grotesk', system-ui, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }
        body {
            font-family: var(--font-sans);
            background: var(--bg-base);
            min-height: 100vh;
            min-height: 100dvh;
            color: var(--text);
            line-height: 1.6;
            margin: 0;
            position: relative;
            overflow-x: hidden;
        }
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background:
                radial-gradient(ellipse 100% 60% at 50% -30%, var(--primary-glow), transparent 45%),
                radial-gradient(ellipse 60% 40% at 80% 50%, var(--danger-glow), transparent 40%),
                linear-gradient(180deg, var(--bg-base) 0%, #0c1222 100%);
            pointer-events: none;
            z-index: 0;
        }
        body::after {
            content: '';
            position: fixed;
            inset: 0;
            background-image: linear-gradient(rgba(14, 165, 233, 0.03) 1px, transparent 1px),
                              linear-gradient(90deg, rgba(14, 165, 233, 0.03) 1px, transparent 1px);
            background-size: 32px 32px;
            pointer-events: none;
            z-index: 0;
        }
        .page {
            position: relative;
            z-index: 1;
            width: 100%;
            min-height: 100vh;
            min-height: 100dvh;
            display: flex;
            flex-direction: column;
            animation: pageIn 0.6s cubic-bezier(0.22, 1, 0.36, 1) forwards;
        }
        @keyframes pageIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        .card {
            flex: 1;
            width: 100%;
            max-width: none;
            background: var(--bg-card);
            backdrop-filter: blur(28px);
            -webkit-backdrop-filter: blur(28px);
            border: none;
            border-radius: 0;
            padding: clamp(28px, 6vw, 56px) clamp(24px, 5vw, 48px);
            box-shadow: none;
            overflow-x: hidden;
            overflow-wrap: break-word;
            display: flex;
            flex-direction: column;
        }
        .card-content {
            max-width: 720px;
            margin: 0 auto;
            width: 100%;
        }
        .hero {
            text-align: center;
            margin-bottom: 32px;
        }
        .hero-icon-wrap {
            width: 88px;
            height: 88px;
            margin: 0 auto 24px;
            background: linear-gradient(145deg, var(--danger-soft) 0%, rgba(239, 68, 68, 0.06) 100%);
            border: 1px solid rgba(239, 68, 68, 0.25);
            border-radius: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: iconPulse 2.5s ease-in-out infinite;
        }
        .hero-icon-wrap svg { width: 44px; height: 44px; stroke: #fca5a5; }
        @keyframes iconPulse {
            0%, 100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.2); }
            50% { transform: scale(1.03); box-shadow: 0 0 24px -4px rgba(239, 68, 68, 0.3); }
        }
        .hero h1 {
            font-size: 1.875rem;
            font-weight: 700;
            letter-spacing: -0.03em;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #fff 0%, #fecaca 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .hero p {
            color: var(--text-muted);
            font-size: 0.9375rem;
            max-width: 320px;
            margin: 0 auto;
        }
        .badge-row {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            justify-content: center;
            margin-top: 18px;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 8px 14px;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 600;
            font-family: var(--font-mono);
            letter-spacing: 0.02em;
        }
        .badge-risk {
            background: var(--danger-soft);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.35);
        }
        .badge-type {
            background: rgba(139, 92, 246, 0.15);
            color: #c4b5fd;
            border: 1px solid rgba(139, 92, 246, 0.3);
        }
        .alert-block {
            background: var(--danger-soft);
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: var(--radius-sm);
            padding: 18px 20px;
            margin-bottom: 24px;
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            align-items: flex-start;
        }
        .alert-block .icon { font-size: 1.35rem; flex-shrink: 0; }
        .alert-block strong { color: #fecaca; font-size: 0.9375rem; }
        .alert-block p { color: var(--text-muted); font-size: 0.875rem; margin-top: 6px; line-height: 1.5; }
        .toggle-details {
            width: 100%;
            padding: clamp(14px, 3vw, 18px) 20px;
            margin-bottom: 12px;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            color: var(--text-muted);
            font-family: var(--font-sans);
            font-size: clamp(0.8125rem, 2vw, 0.9375rem);
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: background 0.2s, color 0.2s;
            -webkit-tap-highlight-color: transparent;
            min-height: 48px;
        }
        .toggle-details:hover,
        .toggle-details:focus { background: rgba(255, 255, 255, 0.08); color: var(--text); }
        .toggle-details:focus { outline: 2px solid var(--primary); outline-offset: 2px; }
        .toggle-details[aria-expanded="true"] .chevron { transform: rotate(180deg); }
        .chevron { transition: transform 0.25s ease; }
        .details {
            background: rgba(0, 0, 0, 0.3);
            border-radius: var(--radius-sm);
            padding: 20px;
            margin-bottom: 24px;
            border: 1px solid var(--border);
            display: none !important;
        }
        .details.is-open { display: block !important; animation: fadeIn 0.3s ease; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .details-title {
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-muted);
            margin-bottom: 14px;
        }
        .detail {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 12px;
            padding: 10px 0;
            border-bottom: 1px solid var(--border);
            font-size: 0.875rem;
        }
        .detail:last-child { border-bottom: none; padding-bottom: 0; }
        .detail-label { color: var(--text-muted); flex-shrink: 0; }
        .detail-value {
            font-family: var(--font-mono);
            font-size: 0.8125rem;
            color: var(--text);
            text-align: right;
            word-break: break-all;
        }
        .detail-value.danger { color: #fca5a5; }
        .reassurance {
            background: var(--success-soft);
            border: 1px solid rgba(16, 185, 129, 0.2);
            border-radius: var(--radius-sm);
            padding: 18px;
            margin-bottom: 28px;
        }
        .reassurance-title {
            color: #6ee7b7;
            font-size: 0.875rem;
            font-weight: 600;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .reassurance ul {
            list-style: none;
            color: var(--text-muted);
            font-size: 0.8125rem;
            padding-left: 0;
        }
        .reassurance li { padding: 4px 0; padding-left: 20px; position: relative; }
        .reassurance li::before {
            content: '✓';
            position: absolute;
            left: 0;
            color: var(--success);
            font-weight: 700;
        }
        .actions {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }
        .btn {
            flex: 1;
            min-width: 140px;
            padding: 16px 22px;
            border-radius: var(--radius-sm);
            font-family: var(--font-sans);
            font-weight: 600;
            font-size: 0.9375rem;
            text-decoration: none;
            text-align: center;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s, background 0.2s;
            border: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        .btn:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }
        .btn-primary {
            background: linear-gradient(135deg, var(--primary) 0%, #0284c7 100%);
            color: #fff;
            box-shadow: 0 4px 16px var(--primary-glow);
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 28px var(--primary-glow);
        }
        .btn-ghost {
            background: rgba(255, 255, 255, 0.06);
            color: var(--text-muted);
            border: 1px solid var(--border);
        }
        .btn-ghost:hover {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text);
        }
        .footer {
            margin-top: 30px;
            padding-top: 24px;
            border-top: 1px solid var(--border);
            text-align: center;
        }
        .footer-id {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 14px;
            flex-wrap: wrap;
            margin-bottom: 14px;
        }
        .footer-id code {
            font-family: var(--font-mono);
            font-size: clamp(0.8125rem, 2.2vw, 1rem);
            background: rgba(255, 255, 255, 0.06);
            padding: clamp(12px, 2.5vw, 16px) clamp(16px, 3vw, 24px);
            border-radius: 12px;
            color: var(--text-muted);
            border: 1px solid var(--border);
            min-height: 48px;
            display: inline-flex;
            align-items: center;
            letter-spacing: 0.05em;
        }
        .btn-copy {
            padding: clamp(12px, 2.5vw, 16px) clamp(18px, 3vw, 24px);
            font-size: clamp(0.75rem, 2vw, 0.875rem);
            font-weight: 600;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.06);
            color: var(--text-muted);
            border: 1px solid var(--border);
            cursor: pointer;
            font-family: var(--font-sans);
            transition: background 0.2s, color 0.2s, border-color 0.2s;
            min-height: 48px;
        }
        .btn-copy:hover { background: rgba(255, 255, 255, 0.1); color: var(--text); }
        .btn-copy.copied { background: var(--success-soft); color: var(--success); border-color: rgba(16, 185, 129, 0.35); }
        .toast {
            position: fixed;
            bottom: 28px;
            left: 50%;
            transform: translateX(-50%) translateY(80px);
            background: var(--success-soft);
            color: var(--success);
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 12px 20px;
            border-radius: var(--radius-sm);
            font-size: 0.875rem;
            font-weight: 600;
            opacity: 0;
            transition: transform 0.3s ease, opacity 0.3s ease;
            z-index: 100;
            pointer-events: none;
        }
        .toast.show {
            transform: translateX(-50%) translateY(0);
            opacity: 1;
        }
        .footer-meta {
            font-size: 0.75rem;
            color: var(--text-muted);
            opacity: 0.85;
            line-height: 1.5;
        }
        .footer-meta a { color: var(--primary); text-decoration: none; }
        .footer-meta a:hover { text-decoration: underline; }
        .captcha-block {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            padding: 20px;
            margin-bottom: 24px;
            max-width: 100%;
        }
        .captcha-block p { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 14px; }
        .captcha-block .g-recaptcha { display: inline-block; max-width: 100%; overflow-x: auto; }
        .captcha-success { margin-top: 14px; }
        @media (min-width: 768px) {
            .hero-icon-wrap { width: 96px; height: 96px; }
            .hero-icon-wrap svg { width: 48px; height: 48px; }
            .hero h1 { font-size: 2rem; }
        }
        @media (max-width: 600px) {
            .card { padding: 28px 20px; }
            .hero { margin-bottom: 24px; }
            .hero h1 { font-size: 1.625rem; }
            .hero p { max-width: 100%; font-size: 0.9rem; }
            .badge-row { margin-top: 14px; gap: 6px; }
            .alert-block { padding: 14px 16px; margin-bottom: 20px; }
            .reassurance { padding: 16px; margin-bottom: 22px; }
            .actions { flex-direction: column; gap: 10px; }
            .btn { min-width: 100%; padding: 16px 20px; }
            .captcha-block { padding: 16px; margin-bottom: 20px; }
            .captcha-block p { font-size: 0.875rem; }
        }
        @media (max-width: 480px) {
            .card { padding: 24px 16px; }
            .hero-icon-wrap { width: 76px; height: 76px; }
            .hero-icon-wrap svg { width: 38px; height: 38px; }
            .hero h1 { font-size: 1.5rem; }
            .hero p { font-size: 0.875rem; }
            .badge { padding: 6px 12px; font-size: 0.7rem; }
            .toggle-details { padding: 12px 16px; font-size: 0.8125rem; }
            .details { padding: 16px; }
            .detail { flex-direction: column; gap: 4px; padding: 8px 0; }
            .detail-value { text-align: left; }
            .footer-id { flex-direction: column; align-items: stretch; }
            .footer-id code, .btn-copy { width: 100%; justify-content: center; min-height: 44px; }
            .footer-meta { font-size: 0.7rem; }
        }
        @media (max-width: 360px) {
            .card { padding: 20px 14px; }
            .hero h1 { font-size: 1.35rem; }
            .hero-icon-wrap { width: 64px; height: 64px; }
            .hero-icon-wrap svg { width: 32px; height: 32px; }
            .captcha-block { padding: 14px; }
        }
    </style>
    <?php if ($hasCaptcha): ?>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <?php endif; ?>
</head>
<body>
    <div class="page">
        <div class="card">
            <div class="card-content">
            <div class="hero">
                <div class="hero-icon-wrap">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/><path d="M12 16h.01"/></svg>
                </div>
                <h1>Requête bloquée</h1>
                <p>Une tentative d’attaque a été détectée et neutralisée par notre protection.</p>
                <div class="badge-row">
                    <span class="badge badge-risk"><?php echo htmlspecialchars($riskLevel); ?></span>
                    <span class="badge badge-type"><?php echo htmlspecialchars($attackType); ?></span>
                    <?php if ($score > 0): ?>
                    <span class="badge badge-type">Score <?php echo (int) $score; ?></span>
                    <?php endif; ?>
                </div>
            </div>

            <div class="alert-block">
                <span class="icon">⚠️</span>
                <div>
                    <strong>Sécurité renforcée activée</strong>
                    <p>Cette requête a été bloquée pour prévenir une attaque par injection SQL. Aucune donnée n’a été exposée.</p>
                </div>
            </div>

            <button type="button" class="toggle-details" id="toggle-details" aria-expanded="false" aria-controls="details-block">
                <span class="chevron">▼</span> Voir les détails techniques
            </button>
            <div class="details" id="details-block" role="region" aria-label="Détails incident">
                <div class="details-title">Détails de l’incident</div>
                <div class="detail">
                    <span class="detail-label">Type</span>
                    <span class="detail-value danger"><?php echo htmlspecialchars($attackType); ?></span>
                </div>
                <div class="detail">
                    <span class="detail-label">Payload détecté</span>
                    <span class="detail-value"><?php echo $payloadSafe; ?></span>
                </div>
                <div class="detail">
                    <span class="detail-label">IP</span>
                    <span class="detail-value"><?php echo htmlspecialchars($ip); ?></span>
                </div>
                <div class="detail">
                    <span class="detail-label">Heure</span>
                    <span class="detail-value"><?php echo $timestamp; ?></span>
                </div>
                <div class="detail">
                    <span class="detail-label">Navigateur</span>
                    <span class="detail-value"><?php echo $userAgentShort; ?></span>
                </div>
            </div>

            <div class="reassurance">
                <div class="reassurance-title">Pour votre sécurité</div>
                <ul>
                    <li>Cet incident a été enregistré dans nos journaux de sécurité.</li>
                    <li>Aucune donnée personnelle n’a été compromise.</li>
                    <li>Notre équipe de sécurité a été informée.</li>
                </ul>
            </div>

            <?php if ($hasCaptcha): ?>
            <div class="captcha-block">
                <p>Pour retourner au formulaire de connexion, vérifiez que vous n'êtes pas un robot.</p>
                <div class="g-recaptcha" data-sitekey="<?php echo htmlspecialchars($recaptchaSiteKey, ENT_QUOTES, 'UTF-8'); ?>" data-callback="onCaptchaSuccess"></div>
                <p class="captcha-success" id="captcha-success-msg" style="display:none;">
                    <a href="#" id="link-retry" class="btn btn-primary" style="display:inline-flex;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
                        Retour à la connexion
                    </a>
                </p>
            </div>
            <?php endif; ?>

            <div class="actions">
                <button type="button" onclick="history.back()" class="btn btn-ghost">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
                    Retour
                </button>
                <a href="/" class="btn btn-primary">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
                    Accueil
                </a>
            </div>

            <div class="footer">
                <div class="footer-id">
                    <code id="incident-id">SEC-<?php echo $incidentId; ?></code>
                    <button type="button" class="btn-copy" id="btn-copy" aria-label="Copier l’ID">Copier l’ID</button>
                </div>
                <p class="footer-meta">SHIELD CORE 2026 • Protection SQL Injection • Si vous pensez qu’il s’agit d’une erreur, <a href="#">contactez le support</a> avec l’ID incident.</p>
            </div>
            </div>
        </div>
    </div>

    <div class="toast" id="toast" aria-live="polite">ID incident copié dans le presse-papier</div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            var toggleBtn = document.getElementById('toggle-details');
            var detailsBlock = document.getElementById('details-block');
            if (toggleBtn && detailsBlock) {
                toggleBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    var isOpen = detailsBlock.classList.toggle('is-open');
                    toggleBtn.setAttribute('aria-expanded', isOpen);
                    var chevron = toggleBtn.querySelector('.chevron');
                    if (chevron) chevron.textContent = isOpen ? '\u25B2' : '\u25BC';
                });
            }
            var idEl = document.getElementById('incident-id');
            var copyBtn = document.getElementById('btn-copy');
            var toastEl = document.getElementById('toast');
            if (idEl && copyBtn) {
                copyBtn.addEventListener('click', function() {
                    var id = idEl.textContent;
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(id).then(function() {
                            copyBtn.textContent = 'Copi\u00e9';
                            copyBtn.classList.add('copied');
                            if (toastEl) {
                                toastEl.classList.add('show');
                                setTimeout(function() { toastEl.classList.remove('show'); }, 2200);
                            }
                            setTimeout(function() {
                                copyBtn.textContent = 'Copier l\'ID';
                                copyBtn.classList.remove('copied');
                            }, 2200);
                        });
                    }
                });
            }
            if (window.history && window.history.replaceState) {
                window.history.replaceState(null, '', window.location.href);
            }
        });
        <?php if ($hasCaptcha): ?>
        function onCaptchaSuccess() {
            var msg = document.getElementById('captcha-success-msg');
            var link = document.getElementById('link-retry');
            if (msg) msg.style.display = 'block';
            if (link) link.href = (window.location.pathname || '/').replace(/\/[^\/]*$/, '') + '/login.php';
        }
        <?php endif; ?>
    </script>
</body>
</html>
        <?php
    }
    
    private static function logIncident(
        string $attackType,
        string $payload,
        array $context
    ): void {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $source = ($attackType === 'AI_DETECTED_THREAT') ? 'BLOCKED_BY_AI' : 'WAF';
        $logEntry = sprintf(
            "[%s] SECURITY_BLOCK - Type: %s | Source: %s | IP: %s | Payload: %s | Context: %s\n",
            date('Y-m-d H:i:s'),
            $attackType,
            $source,
            $ip,
            substr($payload, 0, 200),
            json_encode($context)
        );

        // Écriture dans le fichier de log
        $logDir = __DIR__ . '/../../../var/logs';
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        $logFile = $logDir . '/security_blocks.log';
        file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);

        // Enregistrement en base pour le dashboard (security_incidents)
        // Géolocalisation : pays de l'IP pour analytics / carte des menaces
        $countryCode = 'XX';
        try {
            $db = ApplicationConfig::getDatabase();
            $geo = new IpGeolocation($db);
            $loc = $geo->resolve($ip);
            $countryCode = $loc['country_code'] ?? 'XX';
        } catch (\Throwable $e) {
            // ignorer si table ip_geo_cache absente ou API indisponible
        }

        try {
            $db = ApplicationConfig::getDatabase();
            $score = (int) ($context['score'] ?? 0);
            $riskScore = isset($context['risk_score']) ? round(min(9.99, (float) $context['risk_score'] * 10), 2) : round(min(9.99, $score / 25), 2);
            $threatLevel = $score >= 120 ? 'critical' : ($score >= 80 ? 'high' : ($score >= 50 ? 'medium' : 'low'));
            $detectionMethod = ($attackType === 'AI_DETECTED_THREAT') ? 'AI' : 'WAF';
            $aiConfidence = ($attackType === 'AI_DETECTED_THREAT' && isset($context['confidence'])) ? round(min(1.0, max(0.0, (float) $context['confidence'])), 4) : null;
            $aiRiskFactors = ($attackType === 'AI_DETECTED_THREAT' && !empty($context['risk_factors']) && is_array($context['risk_factors'])) ? json_encode($context['risk_factors'], JSON_UNESCAPED_UNICODE) : null;

            $stmt = $db->prepare(
                "INSERT INTO security_incidents 
                 (uuid, type, ip_address, payload_hash, payload_preview, risk_score, ai_confidence, ai_risk_factors, detection_method, threat_level, action_taken, blocked, country_code, threat_type, subtype, endpoint) 
                 VALUES (:uuid, 'SQL_INJECTION', :ip, :payload_hash, :payload_preview, :risk_score, :ai_confidence, :ai_risk_factors, :detection_method, :threat_level, 'blocked', 1, :country_code, :threat_type, :subtype, :endpoint)"
            );
            $stmt->execute([
                'detection_method' => $detectionMethod,
                'uuid' => Uuid::uuid4()->toString(),
                'ip' => $ip,
                'payload_hash' => hash('sha256', $payload),
                'payload_preview' => substr($payload, 0, 500),
                'risk_score' => $riskScore,
                'ai_confidence' => $aiConfidence,
                'ai_risk_factors' => $aiRiskFactors,
                'threat_level' => $threatLevel,
                'threat_type' => $attackType === 'AI_DETECTED_THREAT' ? ($context['threat_type'] ?? 'AI_DETECTED_THREAT') : $attackType,
                'subtype' => substr((string) ($context['parameter'] ?? '') . '|' . ($context['context'] ?? 'login'), 0, 50),
                'endpoint' => $_SERVER['REQUEST_URI'] ?? null,
                'country_code' => $countryCode,
            ]);
        } catch (\Throwable $e) {
            $errMsg = "SecurityResponseFactory: INSERT security_incidents failed: " . $e->getMessage();
            error_log($errMsg);
            @file_put_contents($logDir . '/security_blocks.log', date('Y-m-d H:i:s') . ' ' . $errMsg . "\n", FILE_APPEND | LOCK_EX);
        }

        error_log("SECURITY: Blocked $attackType attack from " . $ip);
    }
    
    /**
     * Vérifie si la requête doit être traitée normalement
     * (pour les faux positifs ou les tests)
     */
    public static function shouldContinue(): bool
    {
        // Vérifie si c'est un test ou un faux positif
        if (isset($_GET['test_mode']) && $_GET['test_mode'] === '1') {
            return true;
        }
        
        // Vérifie si l'IP est en liste blanche
        $whitelist = ['127.0.0.1', '::1'];
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
        
        if (in_array($clientIp, $whitelist)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Crée une réponse de redirection vers une page sécurisée
     */
    public static function redirectToSecurePage(string $url, string $reason = ''): void
    {
        if (!empty($reason)) {
            $_SESSION['security_redirect_reason'] = $reason;
        }
        
        header('Location: ' . $url);
        exit();
    }
    
    /**
     * Récupère les statistiques de blocage
     */
    public static function getBlockStats(): array
    {
        $logDir = __DIR__ . '/../../../var/logs';
        $logFile = $logDir . '/security_blocks.log';
        
        if (!file_exists($logFile)) {
            return ['total' => 0, 'today' => 0, 'by_type' => []];
        }
        
        $content = file_get_contents($logFile);
        $lines = explode("\n", trim($content));
        
        $stats = [
            'total' => count($lines),
            'today' => 0,
            'by_type' => []
        ];
        
        $today = date('Y-m-d');
        
        foreach ($lines as $line) {
            if (strpos($line, $today) !== false) {
                $stats['today']++;
            }
            
            if (preg_match('/Type: (\w+)/', $line, $matches)) {
                $type = $matches[1];
                $stats['by_type'][$type] = ($stats['by_type'][$type] ?? 0) + 1;
            }
        }
        
        return $stats;
    }
}