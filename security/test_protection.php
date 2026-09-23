<?php
// security/test_protection.php
require_once 'detector.php';
require_once 'logger.php';

$logger = new SecurityLogger();
$detector = new SQLInjectionDetector($logger);

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Test de Protection SQLi</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        .test-case { margin: 10px; padding: 10px; border-radius: 5px; }
        .passed { background: #d4edda; border: 1px solid #c3e6cb; }
        .failed { background: #f8d7da; border: 1px solid #f5c6cb; }
        .expected { font-weight: bold; }
        code { background: #eee; padding: 2px 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>🧪 Test du Système de Détection SQLi</h1>
    
    <?php
    $testCases = [
        ["' OR '1'='1", true, "Injection basique"],
        ["admin' --", true, "Commentaire SQL"],
        ["test", false, "Entrée normale"],
        ["' UNION SELECT * FROM users --", true, "Union injection"],
        ["'; DROP TABLE users --", true, "Drop table"],
        ["<script>alert('xss')</script>", false, "XSS (hors scope SQLi)"],
        ["test' AND '1'='2", true, "Condition booléenne"],
        ["test@example.com", false, "Email normal"],
        ["12345", false, "Nombre"],
        ["' OR SLEEP(5) --", true, "Time-based"]
    ];
    
    $results = [];
    $passed = 0;
    $total = count($testCases);
    
    foreach ($testCases as $test) {
        list($input, $expected, $description) = $test;
        $detected = $detector->detect($input, 'test_param');
        
        $isCorrect = ($detected == $expected);
        if ($isCorrect) $passed++;
        
        $results[] = [
            'input' => $input,
            'detected' => $detected,
            'expected' => $expected,
            'description' => $description,
            'correct' => $isCorrect
        ];
    }
    
    $score = round(($passed / $total) * 100, 1);
    ?>
    
    <h2>Résultats : <?php echo $score; ?>% de réussite</h2>
    <p>Tests passés : <?php echo $passed; ?> / <?php echo $total; ?></p>
    
    <?php foreach ($results as $result): ?>
        <div class="test-case <?php echo $result['correct'] ? 'passed' : 'failed'; ?>">
            <strong><?php echo $result['description']; ?></strong><br>
            Input: <code><?php echo htmlspecialchars($result['input']); ?></code><br>
            Détecté: <?php echo $result['detected'] ? '✅ OUI' : '❌ NON'; ?> |
            Attendu: <?php echo $result['expected'] ? 'OUI' : 'NON'; ?><br>
            <?php if (!$result['correct']): ?>
                <span style="color: #dc3545;">⚠️ Échec du test</span>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
    
    <h3>Logs générés :</h3>
    <?php
    $logs = $logger->getRecentAttacks(10);
    if (empty($logs)) {
        echo "<p>Aucun log généré.</p>";
    } else {
        foreach ($logs as $log) {
            echo "<div style='background:#eee;padding:5px;margin:2px;font-family:monospace;'>";
            echo htmlspecialchars($log);
            echo "</div>";
        }
    }
    ?>
    
    <div style="margin-top: 30px; padding: 20px; background: #e9ecef; border-radius: 5px;">
        <h3>Prochaines étapes :</h3>
        <ol>
            <li>Testez sur l'application : <a href="../app/login.php">login.php</a></li>
            <li>Vérifiez le dashboard : <a href="dashboard.php">dashboard.php</a></li>
            <li>Testez avec différents payloads</li>
        </ol>
    </div>
</body>
</html>