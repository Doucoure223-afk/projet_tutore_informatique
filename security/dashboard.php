<?php
require_once 'logger.php';
require_once '../app/config.php';

$logger = new SecurityLogger();
$conn = getDatabaseConnection();

// Récupérer les stats
$today = date('Y-m-d');
$stats = [
    'total_today' => 0,
    'blocked_today' => 0,
    'top_ips' => [],
    'recent_attacks' => $logger->getRecentAttacks(15),
    'ia_logs' => $logger->getIALogs(10),
    'global_stats' => $logger->getStats(30)
];

// Analyser les logs du jour
$logContent = $logger->getLogContent();

if (!empty($logContent)) {
    $lines = explode("\n", $logContent);
    foreach ($lines as $line) {
        if (strpos($line, $today) !== false) {
            $stats['total_today']++;
            
// ÉTENDRE les conditions de détection (lignes 26-36) :
if (strpos($line, 'BLOCKED') !== false || 
    strpos($line, 'Action: BLOCKED') !== false ||
    strpos($line, 'Action: BLOCK') !== false ||
    strpos($line, 'BLOCKED_BY_IA') !== false ||
    strpos($line, 'Action: BLOCKED_BY_IA') !== false) {
    $stats['blocked_today']++;
}
            
            // Extraire IP
            if (preg_match('/IP: ([0-9\.]+)/', $line, $matches)) {
                $ip = $matches[1];
                $stats['top_ips'][$ip] = ($stats['top_ips'][$ip] ?? 0) + 1;
            }
        }
    }
    
    // Trier les IPs
    arsort($stats['top_ips']);
    $stats['top_ips'] = array_slice($stats['top_ips'], 0, 10);
}

// Calculer le taux de blocage
$blockRateToday = $stats['total_today'] > 0 ? 
    round(($stats['blocked_today'] / $stats['total_today']) * 100, 1) : 0;
$blockRateGlobal = $stats['global_stats']['total'] > 0 ? 
    round(($stats['global_stats']['blocked'] / $stats['global_stats']['total']) * 100, 1) : 0;
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Sécurité</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary-color: #2196F3;
            --danger-color: #f44336;
            --success-color: #4CAF50;
            --warning-color: #ff9800;
            --dark-color: #333;
            --light-color: #f5f5f5;
        }
        
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: var(--light-color);
            color: var(--dark-color);
        }
        
        .header {
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border-left: 5px solid var(--primary-color);
        }
        
        h1 {
            margin: 0;
            color: var(--dark-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0,0,0,0.15);
        }
        
        .card h3 {
            margin-top: 0;
            color: var(--primary-color);
            border-bottom: 2px solid var(--primary-color);
            padding-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .stat {
            font-size: 2.8em;
            font-weight: bold;
            margin: 15px 0;
            text-align: center;
        }
        
        .stat-danger {
            color: var(--danger-color);
        }
        
        .stat-success {
            color: var(--success-color);
        }
        
        .stat-warning {
            color: var(--warning-color);
        }
        
        .stat-info {
            color: var(--primary-color);
        }
        
        .attack-log {
            background: #ffebee;
            padding: 12px;
            margin: 8px 0;
            border-radius: 6px;
            border-left: 4px solid var(--danger-color);
            font-size: 0.9em;
            word-break: break-all;
        }
        
        .ia-log {
            background: #e3f2fd;
            padding: 12px;
            margin: 8px 0;
            border-radius: 6px;
            border-left: 4px solid var(--primary-color);
            font-size: 0.85em;
            word-break: break-word;
        }
        
        .ia-high-risk {
            background: #ffebee;
            border-left-color: var(--danger-color);
        }
        
        .ia-medium-risk {
            background: #fff3e0;
            border-left-color: var(--warning-color);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        th, td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }
        
        th {
            background: #f2f2f2;
            font-weight: 600;
        }
        
        tr:hover {
            background: #f9f9f9;
        }
        
        .chart-container {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-top: 25px;
        }
        
        .navigation {
            text-align: center;
            margin-top: 40px;
            padding: 25px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .btn {
            display: inline-block;
            padding: 12px 25px;
            margin: 0 10px;
            background: var(--primary-color);
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            transition: background 0.3s;
        }
        
        .btn:hover {
            background: #1976D2;
        }
        
        .btn-danger {
            background: var(--danger-color);
        }
        
        .btn-danger:hover {
            background: #d32f2f;
        }
        
        .btn-success {
            background: var(--success-color);
        }
        
        .btn-success:hover {
            background: #388E3C;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .stat-item {
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        
        .stat-value {
            font-size: 1.8em;
            font-weight: bold;
            margin: 5px 0;
        }
        
        .stat-label {
            font-size: 0.9em;
            color: #666;
        }
        
        .timestamp {
            font-size: 0.8em;
            color: #888;
            margin-top: 5px;
        }
        
        code {
            background: #f1f1f1;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .alert {
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            font-weight: bold;
        }
        
        .alert-success {
            background: #d4edda;
            color: #155724;
            border-left: 4px solid var(--success-color);
        }
        
        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border-left: 4px solid var(--danger-color);
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Dashboard de Sécurité SQL Injection</h1>
        <p>Système de protection basé sur règles et IA - Suivi en temps réel</p>
        <div class="timestamp">Dernière mise à jour: <?php echo date('Y-m-d H:i:s'); ?></div>
    </div>
    
    <div class="dashboard">
        <!-- Carte 1 : Aperçu du jour -->
        <div class="card">
            <h3>📊 Aperçu du Jour</h3>
            <div class="stat stat-danger"><?php echo $stats['total_today']; ?></div>
            <p>Tentatives d'attaque aujourd'hui</p>
            
            <div class="stat stat-success"><?php echo $stats['blocked_today']; ?></div>
            <p>Attaques bloquées</p>
            
            <div class="stat stat-info"><?php echo $blockRateToday; ?>%</div>
            <p>Taux de blocage</p>
            
            <?php if ($stats['total_today'] == 0): ?>
                <div class="alert alert-success">✅ Aucune attaque aujourd'hui</div>
            <?php elseif ($blockRateToday == 100): ?>
                <div class="alert alert-success">✅ Toutes les attaques bloquées</div>
            <?php elseif ($blockRateToday < 80): ?>
                <div class="alert alert-danger">⚠️ Taux de blocage inférieur à 80%</div>
            <?php endif; ?>
        </div>
        
        <!-- Carte 2 : Statistiques globales -->
        <div class="card">
            <h3>📈 Statistiques (30 jours)</h3>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value stat-danger"><?php echo $stats['global_stats']['total']; ?></div>
                    <div class="stat-label">Total attaques</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value stat-success"><?php echo $stats['global_stats']['blocked']; ?></div>
                    <div class="stat-label">Bloquées</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value stat-info"><?php echo $blockRateGlobal; ?>%</div>
                    <div class="stat-label">Taux blocage</div>
                </div>
            </div>
            
            <?php if (!empty($stats['global_stats']['by_type'])): ?>
                <h4>Par type d'attaque :</h4>
                <table>
                    <tr><th>Type</th><th>Nombre</th></tr>
                    <?php foreach ($stats['global_stats']['by_type'] as $type => $count): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($type); ?></td>
                        <td><?php echo $count; ?></td>
                    </tr>
                    <?php endforeach; ?>
                </table>
            <?php endif; ?>
        </div>
        
        <!-- Carte 3 : Top IPs -->
        <div class="card">
            <h3>🔴 Top IPs Attaquantes</h3>
            <?php if (!empty($stats['top_ips'])): ?>
                <table>
                    <tr><th>IP</th><th>Nombre</th></tr>
                    <?php foreach ($stats['top_ips'] as $ip => $count): ?>
                    <tr>
                        <td><code><?php echo htmlspecialchars($ip); ?></code></td>
                        <td><?php echo $count; ?></td>
                    </tr>
                    <?php endforeach; ?>
                </table>
            <?php else: ?>
                <p style="color: #666; text-align: center; padding: 20px;">Aucune attaque aujourd'hui 🎉</p>
            <?php endif; ?>
        </div>
        
        <!-- Carte 4 : Dernières attaques -->
        <div class="card">
            <h3>🕒 Dernières Attaques</h3>
            <?php if (!empty($stats['recent_attacks'])): ?>
                <?php foreach ($stats['recent_attacks'] as $log): ?>
                    <div class="attack-log">
                        <?php echo htmlspecialchars($log); ?>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p style="color: #666; text-align: center; padding: 20px;">Aucun log d'attaque disponible</p>
            <?php endif; ?>
        </div>
        
        <!-- Carte 5 : Analyse IA -->
        <div class="card">
            <h3>🤖 Analyse IA (Simulation)</h3>
            <?php if (!empty($stats['ia_logs'])): ?>
                <?php foreach ($stats['ia_logs'] as $log): ?>
                    <?php
                    $class = 'ia-log';
                    if (strpos($log, 'Risk: 0.9') !== false || strpos($log, 'Risk: 0.8') !== false) {
                        $class .= ' ia-high-risk';
                    } elseif (strpos($log, 'Risk: 0.7') !== false || strpos($log, 'Risk: 0.6') !== false) {
                        $class .= ' ia-medium-risk';
                    }
                    ?>
                    <div class="<?php echo $class; ?>">
                        <?php echo htmlspecialchars($log); ?>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p style="color: #666; text-align: center; padding: 20px;">Aucune analyse IA récente</p>
            <?php endif; ?>
        </div>
    </div>
    
    <!-- Graphique -->
    <div class="chart-container">
        <h3>📈 Activité des attaques (Simulation)</h3>
        <canvas id="attackChart" width="400" height="200"></canvas>
    </div>
    
    <script>
    const ctx = document.getElementById('attackChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['J-6', 'J-5', 'J-4', 'J-3', 'J-2', 'Hier', 'Aujourd\'hui'],
            datasets: [
                {
                    label: 'Tentatives d\'attaque',
                    data: [5, 8, 3, 12, 7, 4, <?php echo $stats['total_today']; ?>],
                    borderColor: '#f44336',
                    backgroundColor: 'rgba(244, 67, 54, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Attaques bloquées',
                    data: [4, 7, 2, 10, 6, 3, <?php echo $stats['blocked_today']; ?>],
                    borderColor: '#4CAF50',
                    backgroundColor: 'rgba(76, 175, 80, 0.1)',
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Évolution des attaques sur 7 jours'
                }
            },
            scales: {
                y: { 
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Nombre d\'événements'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Jours'
                    }
                }
            }
        }
    });
    </script>
    
    <div class="navigation">
        <h3>🚀 Actions rapides</h3>
        <a href="../app/login.php" class="btn">← Retour à l'application</a>
        <a href="test_diagram.php" class="btn btn-success">🧪 Tester le diagramme</a>
        <a href="test_protection.php" class="btn btn-warning">🔧 Tester la protection</a>
        <a href="../app/search.php" class="btn btn-info">🔍 Page recherche vulnérable</a>
        
        <div style="margin-top: 20px; font-size: 14px; color: #666;">
            <strong>Statut système :</strong> 
            ✅ Protection active | 
            ✅ Logging actif | 
            ✅ IA simulée | 
            ✅ Dashboard opérationnel
        </div>
    </div>
</body>
</html>