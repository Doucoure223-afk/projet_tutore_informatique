<?php
declare(strict_types=1);

/**
 * RECHERCHE SÉCURISÉE - Protection SQL Injection
 * Requêtes préparées + Détection SQL + IA (comme login.php)
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (empty($_SESSION['authenticated']) || empty($_SESSION['user_id'])) {
    $baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
    header('Location: ' . $baseUrl . '/login.php', true, 303);
    exit;
}

require_once __DIR__ . '/../vendor/autoload.php';

use App\Infrastructure\ApplicationConfig;
use App\Security\Detector\SqlInjectionDetector;
use App\Security\Logger\SecurityLoggerInterface;
use App\Security\AI\ThreatIntelligenceEngine;
use App\Security\AI\FlaskAiClient;
use App\Security\Response\SecurityResponseFactory;

ApplicationConfig::initialize(__DIR__ . '/..');
$db = ApplicationConfig::getDatabase();
$logger = ApplicationConfig::getLogger('security');
$detector = new SqlInjectionDetector($logger);
$aiEngine = new ThreatIntelligenceEngine();
$flaskAiUrl = ApplicationConfig::get('ai.flask_url', 'http://127.0.0.1:5000');
$flaskAiClient = new FlaskAiClient($flaskAiUrl, $logger);

// Middleware de sécurité (détection SQL + IA)
$securityResult = processSearchSecurityMiddleware($detector, $aiEngine, $flaskAiClient, $logger);
if ($securityResult->shouldBlock) {
    $threat = $securityResult->threatInfo;
    $attackType = $threat['type'] ?? 'SQL_INJECTION';
    $param = $threat['parameter'] ?? 'q';
    $payload = isset($_GET[$param]) ? (string) $_GET[$param] : '(requête bloquée)';
    SecurityResponseFactory::createBlockedResponse($attackType, $payload, $threat);
}

// Recherche sécurisée avec requêtes préparées
$searchQuery = isset($_GET['q']) ? trim((string) $_GET['q']) : '';
$results = [];
$searchQuery = mb_substr($searchQuery, 0, 100); // Limite de longueur

if ($searchQuery !== '') {
    try {
        $stmt = $db->prepare(
            "SELECT id, name, description, category, price, stock 
             FROM products 
             WHERE name LIKE :q OR description LIKE :q OR category LIKE :q 
             LIMIT 50"
        );
        $pattern = '%' . $searchQuery . '%';
        $stmt->bindValue(':q', $pattern, PDO::PARAM_STR);
        $stmt->execute();
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        $logger->error('SEARCH_QUERY_FAILED', ['error' => $e->getMessage()]);
    }
}

$baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
$dashboardUrl = $baseUrl . '/dashboard.php';
$searchQueryEscaped = htmlspecialchars($searchQuery, ENT_QUOTES, 'UTF-8');

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recherche • SHIELD CORE 2026</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --sc-bg: #060b12;
            --sc-surface: rgba(15, 23, 42, 0.92);
            --sc-border: rgba(148, 163, 184, 0.15);
            --sc-text: #f1f5f9;
            --sc-muted: #94a3b8;
            --sc-primary: #0ea5e9;
            --sc-success: #10b981;
            --sc-font: 'Space Grotesk', system-ui, sans-serif;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: var(--sc-font); background: var(--sc-bg); min-height: 100vh; padding: 24px; color: var(--sc-text); }
        .container { max-width: 900px; margin: 0 auto; }
        .header {
            background: var(--sc-surface);
            border: 1px solid var(--sc-border);
            border-radius: 16px;
            padding: 28px;
            margin-bottom: 24px;
        }
        .header h1 { font-size: 1.75rem; margin-bottom: 8px; }
        .security-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.2);
            color: var(--sc-success);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
            margin-top: 12px;
        }
        .search-box { display: flex; gap: 12px; margin: 20px 0; }
        .search-input {
            flex: 1;
            padding: 14px 18px;
            background: rgba(255,255,255,0.06);
            border: 1px solid var(--sc-border);
            border-radius: 12px;
            color: var(--sc-text);
            font-size: 1rem;
        }
        .search-input:focus { outline: none; border-color: var(--sc-primary); }
        .search-btn {
            padding: 14px 24px;
            background: var(--sc-primary);
            color: #fff;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            cursor: pointer;
        }
        .search-btn:hover { opacity: 0.9; }
        .links { margin-top: 20px; }
        .links a { color: var(--sc-primary); text-decoration: none; margin-right: 20px; }
        .links a:hover { text-decoration: underline; }
        .results-info {
            background: var(--sc-surface);
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid var(--sc-border);
        }
        .product-card {
            background: var(--sc-surface);
            border: 1px solid var(--sc-border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            display: flex;
            gap: 20px;
        }
        .product-image { font-size: 2.5rem; }
        .product-name { font-weight: 600; font-size: 1.1rem; margin-bottom: 8px; }
        .product-description { color: var(--sc-muted); font-size: 0.9375rem; margin-bottom: 12px; }
        .product-meta { display: flex; gap: 20px; color: var(--sc-muted); font-size: 0.875rem; }
        .no-results {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            padding: 30px;
            border-radius: 12px;
            text-align: center;
        }
        .info-box {
            background: rgba(14, 165, 233, 0.1);
            border: 1px solid rgba(14, 165, 233, 0.3);
            padding: 16px;
            border-radius: 12px;
            margin-top: 20px;
            font-size: 0.9375rem;
            color: var(--sc-muted);
        }
    </style>
</head>
<body>
    <div class="protection-banner" style="position: fixed; top: 0; left: 0; right: 0; background: linear-gradient(90deg, #059669, #047857); color: #fff; padding: 10px; text-align: center; font-weight: 700; font-size: 0.9rem; z-index: 9999;">
        ✓ PROTÉGÉ — Détection SQL + IA • Requêtes préparées
    </div>
    <div class="container" style="padding-top: 50px;">
        <div class="header">
            <h1>🔍 Recherche de produits <span class="security-badge">✓ PROTÉGÉ SQLi</span></h1>
            <p style="color: var(--sc-muted); margin-top: 8px;">Requêtes préparées + Détection IA active</p>

            <form method="GET" action="">
                <div class="search-box">
                    <input type="text" name="q" class="search-input"
                           placeholder="Rechercher un produit..."
                           value="<?= $searchQueryEscaped ?>">
                    <button type="submit" class="search-btn">Rechercher</button>
                </div>
            </form>

            <div class="links">
                <a href="<?= htmlspecialchars($dashboardUrl) ?>">← Dashboard</a>
                <a href="<?= htmlspecialchars($baseUrl) ?>/login.php">Déconnexion</a>
            </div>
        </div>

        <?php if ($searchQuery !== ''): ?>
            <div class="results-info">
                <h3>Résultats pour "<?= $searchQueryEscaped ?>"</h3>
                <p><?= count($results) ?> produit(s) trouvé(s)</p>
            </div>

            <?php if (!empty($results)): ?>
                <?php foreach ($results as $product): ?>
                    <div class="product-card">
                        <div class="product-image">📱</div>
                        <div>
                            <div class="product-name"><?= htmlspecialchars($product['name']) ?></div>
                            <div class="product-description"><?= htmlspecialchars($product['description'] ?? '') ?></div>
                            <div class="product-meta">
                                <span>💰 <?= htmlspecialchars((string) $product['price']) ?> €</span>
                                <span>📦 <?= (int) ($product['stock'] ?? 0) ?> en stock</span>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <div class="no-results">
                    <h3>Aucun résultat trouvé</h3>
                    <p>Essayez une autre recherche. Les payloads SQLi sont bloqués.</p>
                </div>
            <?php endif; ?>
        <?php else: ?>
            <div class="info-box">
                <strong>🛡️ Protection active :</strong> Les entrées sont analysées par le détecteur SQL et l'IA. 
                Les tentatives d'injection sont bloquées (page 403).
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
<?php

// ==================== FONCTIONS ====================

function processSearchSecurityMiddleware(
    SqlInjectionDetector $detector,
    ThreatIntelligenceEngine $aiEngine,
    FlaskAiClient $flaskAiClient,
    SecurityLoggerInterface $logger
): SearchSecurityMiddlewareResult {
    $requestData = array_merge($_GET, $_POST);
    $sessionId = session_id() ?: null;

    foreach ($requestData as $param => $value) {
        if (!is_string($value)) continue;

        $analysis = $detector->analyze($value, $param, 'search');

        if ($analysis->shouldBlock) {
            $logger->logSqlInjection(
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $value,
                $analysis->score,
                $analysis->detectedPatterns ?? [],
                'BLOCKED',
                $param,
                'search'
            );
            return new SearchSecurityMiddlewareResult(true, [
                'type' => 'SQL_INJECTION',
                'score' => $analysis->score,
                'parameter' => $param,
                'risk_level' => $analysis->riskLevel ?? 'high',
            ]);
        }

        if ($analysis->needsAiAnalysis) {
            $context = [
                'type' => 'search',
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
                    'search'
                );
                return new SearchSecurityMiddlewareResult(true, [
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

    return new SearchSecurityMiddlewareResult(false, []);
}

class SearchSecurityMiddlewareResult
{
    public function __construct(
        public readonly bool $shouldBlock,
        public readonly array $threatInfo
    ) {}
}
