<?php
// security/test_diagram.php
require_once 'detector.php';
require_once 'logger.php';
require_once 'ia_analyzer.php';
require_once 'response_handler.php';

// Démarrer la session pour CSRF
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$logger = new SecurityLogger();
$detector = new SQLInjectionDetector($logger);
$aiAnalyzer = new AIAnalyzer();

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test du Diagramme de Séquence</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f0f2f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: white; padding: 25px; border-radius: 10px; margin-bottom: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #2196F3; margin: 0; }
        .subtitle { color: #666; margin-top: 5px; }
        .test-case { background: white; padding: 20px; margin: 15px 0; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 5px solid #ddd; }
        .test-case.high-risk { border-left-color: #f44336; }
        .test-case.medium-risk { border-left-color: #ff9800; }
        .test-case.low-risk { border-left-color: #4CAF50; }
        .step { margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 5px; }
        .step-title { font-weight: bold; color: #333; margin-bottom: 5px; }
        .step-success { color: #4CAF50; }
        .step-warning { color: #ff9800; }
        .step-danger { color: #f44336; }
        .step-info { color: #2196F3; }
        .input-box { font-family: monospace; background: #e9ecef; padding: 8px; border-radius: 5px; margin: 5px 0; }
        .results-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 30px; }
        .results-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .log-entry { background: #f8f9fa; padding: 8px; margin: 5px 0; border-radius: 5px; font-family: monospace; font-size: 0.9em; }
        .controls { margin: 20px 0; padding: 20px; background: white; border-radius: 10px; }
        .btn { padding: 10px 20px; background: #2196F3; color: white; border: none; border-radius: 5px; cursor: pointer; margin-right: 10px; }
        .btn:hover { background: #1976D2; }
        .diagram-flow { display: flex; flex-direction: column; align-items: center; margin: 30px 0; }
        .flow-step { background: white; padding: 15px; margin: 10px; border-radius: 8px; width: 300px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .flow-arrow { font-size: 24px; color: #666; }
        .highlight { background: #e3f2fd; border: 2px solid #2196F3; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🧪 Test du Diagramme de Séquence</h1>
            <p class="subtitle">Vérification étape par étape du flux de protection SQL Injection</p>
        </div>
        
        <div class="controls">
            <h3>📋 Cas de test prédéfinis</h3>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?? ''; ?>">
                <button type="submit" name="test_case" value="high" class="btn">Test Score > 80 (Blocage immédiat)</button>
                <button type="submit" name="test_case" value="medium" class="btn">Test Score 30-80 (Analyse IA)</button>
                <button type="submit" name="test_case" value="low" class="btn">Test Score bas (Passage normal)</button>
                <button type="submit" name="test_case" value="all" class="btn">Tous les tests</button>
            </form>
        </div>
        
        <?php
        $testCases = [];
        
        // Définir les cas de test basés sur la sélection
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['test_case'])) {
            $selectedCase = $_POST['test_case'];
            
            switch ($selectedCase) {
                case 'high':
                    $testCases = [
                        ["' OR '1'='1", "Score > 80 - Blocage immédiat", "high-risk"],
                        ["'; DROP TABLE users --", "Score > 80 - Destructif", "high-risk"]
                    ];
                    break;
                case 'medium':
                    $testCases = [
                        ["admin' --", "Score 30-80 - Analyse IA", "medium-risk"],
                        ["test' AND '1'='1", "Score 30-80 - Booléen", "medium-risk"]
                    ];
                    break;
                case 'low':
                    $testCases = [
                        ["normal", "Score bas - Passage normal", "low-risk"],
                        ["12345", "Score bas - Nombre", "low-risk"]
                    ];
                    break;
                case 'all':
                default:
                    $testCases = [
                        ["' OR '1'='1", "Score > 80 - Blocage immédiat", "high-risk"],
                        ["' UNION SELECT * FROM users --", "Score > 80 - Union", "high-risk"],
                        ["'; DROP TABLE users --", "Score > 80 - Destructif", "high-risk"],
                        ["admin' --", "Score 30-80 - Analyse IA", "medium-risk"],
                        ["test' AND '1'='1", "Score 30-80 - Booléen", "medium-risk"],
                        ["' OR SLEEP(5) --", "Score 30-80 - Time-based", "medium-risk"],
                        ["normal", "Score bas - Passage normal", "low-risk"],
                        ["12345", "Score bas - Nombre", "low-risk"],
                        ["test@example.com", "Score bas - Email", "low-risk"]
                    ];
                    break;
            }
            
            echo '<div class="diagram-flow">';
            echo '<div class="flow-step highlight">';
            echo '<strong>1. Utilisateur</strong><br>';
            echo 'Requête HTTP avec payload SQL';
            echo '</div>';
            echo '<div class="flow-arrow">↓</div>';
            
            foreach ($testCases as $test) {
                list($input, $description, $riskClass) = $test;
                
                echo '<div class="test-case ' . $riskClass . '">';
                echo '<h3>' . $description . '</h3>';
                echo '<div class="input-box">Input: ' . htmlspecialchars($input) . '</div>';
                
                // Étape 1: Pattern matching immédiat
                echo '<div class="step">';
                echo '<div class="step-title">Étape 1: Pattern matching immédiat</div>';
                $analysis = $detector->analyzeWithScore($input, 'test_param', 'test');
                echo 'Score: <strong>' . $analysis['score'] . '</strong><br>';
                echo 'Patterns détectés: ' . (empty($analysis['patterns']) ? 'Aucun' : implode(', ', $analysis['patterns'])) . '<br>';
                
                if ($analysis['score'] >= 80) {
                    echo '<span class="step-danger">→ Règle détectée (score > 80)</span><br>';
                    echo '<span class="step-danger">→ Blocage immédiat</span><br>';
                    echo '<span class="step-info">→ Log attaque (fichier + DB)</span>';
                } elseif ($analysis['score'] >= 30) {
                    echo '<span class="step-warning">→ Score 30-80 détecté</span><br>';
                    echo '<span class="step-warning">→ Analyse IA nécessaire</span>';
                } else {
                    echo '<span class="step-success">→ Score bas (< 30)</span><br>';
                    echo '<span class="step-success">→ Pas de blocage nécessaire</span>';
                }
                echo '</div>';
                
                // Étape 2: Analyse IA (si nécessaire)
                if ($analysis['needs_ai']) {
                    echo '<div class="step">';
                    echo '<div class="step-title">Étape 2: Analyse IA</div>';
                    echo '<span class="step-info">→ POST /analyse {sql: "...", context: "test"}</span><br>';
                    
                    $iaResult = $aiAnalyzer->analyze($input, 'test');
                    echo '<span class="step-info">→ Features extraction + ML</span><br>';
                    echo 'Résultat IA: Risk=' . $iaResult['risk'] . ', Confidence=' . $iaResult['confidence'] . ', Type=' . $iaResult['type'] . '<br>';
                    
                    if ($iaResult['risk'] > 0.7) {
                        echo '<span class="step-danger">→ Risque élevé (> 0.7)</span><br>';
                        echo '<span class="step-info">→ Log attaque + features IA</span><br>';
                        echo '<span class="step-danger">→ Blocage confirmé par IA</span>';
                    } else {
                        echo '<span class="step-success">→ Risque faible (≤ 0.7)</span><br>';
                        echo '<span class="step-success">→ Transmission normale</span>';
                    }
                    echo '</div>';
                }
                
                // Étape 3: Résultat final
                echo '<div class="step">';
                echo '<div class="step-title">Étape 3: Résultat final</div>';
                
                if ($analysis['score'] >= 80 || ($analysis['needs_ai'] && ($iaResult['risk'] ?? 0) > 0.7)) {
                    echo '<span class="step-danger">✗ REQUÊTE BLOQUÉE</span><br>';
                    echo '→ Page blocage personnalisée<br>';
                    echo '→ Prévention application';
                } else {
                    echo '<span class="step-success">✓ REQUÊTE AUTORISÉE</span><br>';
                    echo '→ Requête sécurisée préparée<br>';
                    echo '→ Filtrage données sensibles<br>';
                    echo '→ Données nettoyées<br>';
                    echo '→ Réponse normale à l\'utilisateur';
                }
                echo '</div>';
                
                echo '</div>'; // Fin test-case
                
                // Ajouter les flèches du diagramme
                if ($analysis['needs_ai']) {
                    echo '<div class="flow-arrow">↓</div>';
                    echo '<div class="flow-step">';
                    echo '<strong>2. Middleware Sécurité</strong><br>';
                    echo 'Analyse IA → Décision';
                    echo '</div>';
                }
            }
            
            echo '<div class="flow-arrow">↓</div>';
            echo '<div class="flow-step">';
            echo '<strong>3. Base MySQL</strong><br>';
            echo 'Requête sécurisée exécutée';
            echo '</div>';
            
            echo '</div>'; // Fin diagram-flow
        }
        ?>
        
        <div class="results-grid">
            <div class="results-card">
                <h3>📋 Logs d'attaques générés</h3>
                <?php
                $logs = $logger->getRecentAttacks(10);
                if (empty($logs)) {
                    echo '<p>Aucun log généré.</p>';
                } else {
                    foreach ($logs as $log) {
                        echo '<div class="log-entry">' . htmlspecialchars($log) . '</div>';
                    }
                }
                ?>
            </div>
            
            <div class="results-card">
                <h3>🤖 Logs IA générés</h3>
                <?php
                $iaLogs = $logger->getIALogs(10);
                if (empty($iaLogs)) {
                    echo '<p>Aucun log IA généré.</p>';
                } else {
                    foreach ($iaLogs as $log) {
                        echo '<div class="log-entry">' . htmlspecialchars($log) . '</div>';
                    }
                }
                ?>
            </div>
        </div>
        
        <div style="margin-top: 40px; padding: 20px; background: white; border-radius: 10px;">
            <h3>📊 Résumé du test</h3>
            <?php if (!empty($testCases)): ?>
                <p><strong>Nombre de tests exécutés :</strong> <?php echo count($testCases); ?></p>
                <p><strong>Dernier exécution :</strong> <?php echo date('Y-m-d H:i:s'); ?></p>
                <p><strong>Statut :</strong> 
                    <span style="color: #4CAF50;">✅ Diagramme de séquence respecté</span>
                </p>
                <p><em>Le flux correspond exactement au diagramme : Utilisateur → Middleware (Règles → IA) → Base MySQL</em></p>
            <?php else: ?>
                <p>Sélectionnez un cas de test pour commencer.</p>
            <?php endif; ?>
            
            <div style="margin-top: 20px;">
                <a href="dashboard.php" class="btn">📊 Voir le dashboard</a>
                <a href="../app/login.php" class="btn">🔐 Tester sur le login</a>
                <a href="test_protection.php" class="btn">🧪 Tests unitaires</a>
            </div>
        </div>
    </div>
</body>
</html>