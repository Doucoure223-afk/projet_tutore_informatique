<?php
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/ia_analyzer.php';
require_once __DIR__ . '/access.php';
require_once __DIR__ . '/explanations.php';

console_require_access();

$logger = console_logger();
$stats = $logger->getStats(7);
$daily = $logger->getDailyStats(7);
$health = console_health();
$filters = [
    'action' => in_array($_GET['action'] ?? '', ['BLOCKED', 'BLOCKED_BY_AI', 'ALLOWED', 'MONITORED'], true) ? $_GET['action'] : '',
    'type' => is_string($_GET['type'] ?? null) ? substr($_GET['type'], 0, 80) : '',
    'search' => is_string($_GET['search'] ?? null) ? substr($_GET['search'], 0, 100) : '',
    'from' => preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['from'] ?? '') ? $_GET['from'] : '',
    'to' => preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['to'] ?? '') ? $_GET['to'] : '',
];

if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="cybershield-incidents.csv"');
    echo "\xEF\xBB\xBF", $logger->exportCsv($filters);
    exit;
}
if (isset($_GET['export']) && $_GET['export'] === 'jsonl') {
    header('Content-Type: application/x-ndjson; charset=utf-8');
    header('Content-Disposition: attachment; filename="cybershield-incidents.jsonl"');
    header('X-Content-Type-Options: nosniff');
    echo $logger->exportJsonLines($filters);
    exit;
}

$page = isset($_GET['page']) && is_scalar($_GET['page']) ? max(1, min(5000, (int) $_GET['page'])) : 1;
$pageSize = 20;
$events = $logger->getEvents($filters, $pageSize + 1, ($page - 1) * $pageSize);
$hasNextPage = count($events) > $pageSize;
if ($hasNextPage) { array_pop($events); }
$healthReady = !empty($health['model_loaded']);
$monitorMode = !(bool) (require __DIR__ . '/../config/security.php')['block_mode'];
$types = array_keys($stats['by_type']);
$totalEvents = (int) $stats['total'];
$decisionDenominator = max(1, $totalEvents);
$chartMax = max(4, (int) (ceil(max(array_map(static fn(array $day): int => (int) $day['total'], $daily) ?: [0]) / 4) * 4));
$plotLeft = 48;
$plotRight = 724;
$plotTop = 22;
$plotBottom = 190;
$plotHeight = $plotBottom - $plotTop;
$plotWidth = $plotRight - $plotLeft;
$totalCoordinates = [];
$blockedCoordinates = [];
foreach ($daily as $index => $day) {
    $x = $plotLeft + $plotWidth * $index / max(1, count($daily) - 1);
    $totalY = $plotBottom - ($plotHeight * (int) $day['total'] / $chartMax);
    $blockedY = $plotBottom - ($plotHeight * (int) $day['blocked'] / $chartMax);
    $totalCoordinates[] = sprintf('%.1f,%.1f', $x, $totalY);
    $blockedCoordinates[] = sprintf('%.1f,%.1f', $x, $blockedY);
}
$topType = array_key_first($stats['by_type']);
$monthsFr = ['janv.', 'févr.', 'mars', 'avr.', 'mai', 'juin', 'juil.', 'août', 'sept.', 'oct.', 'nov.', 'déc.'];
$weekdaysFr = ['dim.', 'lun.', 'mar.', 'mer.', 'jeu.', 'ven.', 'sam.'];
$exportFilters = array_filter($filters, static fn($value) => $value !== '');
$exportBase = 'dashboard.php' . ($exportFilters ? '?' . http_build_query($exportFilters) . '&' : '?');
$paginationBase = $exportBase;
$chartHasData = $totalEvents > 0;
?>
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="theme-color" content="#f1efe8">
  <title>Supervision · CyberShield AI</title>
  <link rel="stylesheet" href="console.css?v=<?= (int) filemtime(__DIR__ . '/console.css') ?>">
</head>
<body>
<a class="skip-link" href="#main-content">Aller au contenu</a>
<div class="shell dashboard-shell">
  <?php console_sidebar('dashboard'); ?>
  <main class="main" id="main-content">
    <header class="dashboard-toolbar">
      <nav class="breadcrumbs" aria-label="Fil d’Ariane">
        <a href="../index.php">Accueil</a><span aria-hidden="true">/</span><span aria-current="page">Supervision</span>
      </nav>
      <form class="quick-search" role="search" method="get" action="dashboard.php#incidents">
        <label class="sr-only" for="quick-search">Rechercher dans les événements</label>
        <input type="search" id="quick-search" name="search" value="<?= console_escape($filters['search']) ?>" placeholder="Rechercher une IP ou une route">
        <input type="hidden" name="action" value="<?= console_escape($filters['action']) ?>">
        <input type="hidden" name="type" value="<?= console_escape($filters['type']) ?>">
        <input type="hidden" name="from" value="<?= console_escape($filters['from']) ?>">
        <input type="hidden" name="to" value="<?= console_escape($filters['to']) ?>">
        <button class="search-submit" type="submit" aria-label="Rechercher">⌕</button>
      </form>
      <a class="button toolbar-action" href="lab.php">Tester une saisie <span aria-hidden="true">↗</span></a>
    </header>

    <section class="page-heading" aria-labelledby="page-title">
      <div>
        <p class="eyebrow">CYBERSHIELD AI <span class="eyebrow-divider">/</span> SUPERVISION · 7 JOURS</p>
        <h1 id="page-title">État de la protection</h1>
        <p class="muted">Les décisions du filtre et les événements consignés, réunis au même endroit.</p>
      </div>
      <div class="heading-date"><span class="date-label">Aujourd’hui</span><time datetime="<?= gmdate('Y-m-d') ?>"><?= gmdate('d/m/Y') ?></time></div>
    </section>

    <?php if ($monitorMode): ?>
      <div class="callout warn mode-notice" role="status">
        <span class="notice-mark" aria-hidden="true">i</span>
        <div><strong>Blocage SQLi : désactivé · mode observation</strong><p>Les signaux SQLi sont enregistrés sans interrompre la requête. Les règles d’accès IP, les limites de débit et de taille restent appliquées.</p></div>
      </div>
    <?php else: ?>
      <div class="callout mode-notice" role="status">
        <span class="notice-mark" aria-hidden="true">✓</span>
        <div><strong>Blocage SQLi : actif</strong><p>Les requêtes signalées sont arrêtées avant d’atteindre la base.</p></div>
      </div>
    <?php endif; ?>

    <?php if (!$healthReady): ?>
      <div class="callout warn service-notice" role="status">
        <strong>Le modèle MLP est indisponible.</strong>
        <span>Le filtre par règles continue de fonctionner. Vérifie que le service d’analyse est démarré avant une démonstration.</span>
      </div>
    <?php endif; ?>

    <section class="metric-strip" aria-label="Indicateurs des sept derniers jours">
      <article class="metric metric-total">
        <span class="metric-label">Événements consignés</span>
        <strong class="metric-value"><?= number_format($totalEvents, 0, ',', ' ') ?></strong>
        <span class="metric-caption">sur les 7 derniers jours</span>
      </article>
      <article class="metric metric-signal">
        <span class="metric-label">Signaux à examiner</span>
        <strong class="metric-value"><?= number_format((int) $stats['attacks'], 0, ',', ' ') ?></strong>
        <span class="metric-caption">risque élevé ou revue utile</span>
      </article>
      <article class="metric metric-blocked">
        <span class="metric-label">Requêtes bloquées</span>
        <strong class="metric-value"><?= number_format((int) $stats['blocked'], 0, ',', ' ') ?></strong>
        <span class="metric-caption"><?= console_escape((string) $stats['block_rate']) ?> % des événements consignés</span>
      </article>
      <article class="metric metric-mlp">
        <span class="metric-label">Analyses MLP journalisées</span>
        <strong class="metric-value"><?= number_format((int) $stats['ai_analyzed'], 0, ',', ' ') ?></strong>
        <span class="metric-caption"><?= $healthReady ? 'Modèle disponible' : 'Modèle à démarrer' ?></span>
      </article>
    </section>

    <?php if (!$chartHasData): ?>
      <section class="first-run-note" aria-labelledby="first-run-title">
        <div class="first-run-symbol" aria-hidden="true">↗</div>
        <div><h2 id="first-run-title">En attente des premières requêtes</h2><p>Les graphiques se rempliront quand tu lanceras un test ou parcourras la boutique de démonstration.</p></div>
        <div class="actions"><a class="button" href="lab.php">Ouvrir le laboratoire</a><a class="button secondary" href="../app/search.php">Parcourir la boutique</a></div>
      </section>
    <?php endif; ?>

    <div class="overview-grid">
      <section class="card chart-panel" aria-labelledby="traffic-title">
        <div class="card-head chart-head">
          <div><p class="eyebrow">VOLUME ET DÉCISIONS</p><h2 id="traffic-title">Activité quotidienne</h2><p class="sub">Événements enregistrés sur les sept derniers jours.</p></div>
          <span class="period-label">7 jours</span>
        </div>
        <div class="chart-legend" aria-hidden="true"><span><i class="legend-total"></i>Toutes les requêtes</span><span><i class="legend-blocked"></i>Bloquées</span></div>
        <div class="chart-scroll">
          <svg class="traffic-chart" viewBox="0 0 760 238" role="img" aria-labelledby="traffic-svg-title traffic-svg-desc">
            <title id="traffic-svg-title">Événements et blocages par jour</title>
            <desc id="traffic-svg-desc">Comparaison du nombre d’événements consignés et de requêtes bloquées sur sept jours.</desc>
            <?php for ($tick = 0; $tick <= 4; $tick++): $tickValue = (int) round($chartMax * $tick / 4); $y = $plotBottom - $plotHeight * $tick / 4; ?>
              <line class="chart-gridline" x1="<?= $plotLeft ?>" y1="<?= number_format($y, 1, '.', '') ?>" x2="<?= $plotRight ?>" y2="<?= number_format($y, 1, '.', '') ?>"></line>
              <text class="chart-axis-label" x="36" y="<?= number_format($y + 4, 1, '.', '') ?>" text-anchor="end"><?= $tickValue ?></text>
            <?php endfor; ?>
            <polyline class="chart-line chart-line-total" fill="none" points="<?= console_escape(implode(' ', $totalCoordinates)) ?>"></polyline>
            <polyline class="chart-line chart-line-blocked" fill="none" points="<?= console_escape(implode(' ', $blockedCoordinates)) ?>"></polyline>
            <?php foreach ($daily as $index => $day): $x = $plotLeft + $plotWidth * $index / max(1, count($daily) - 1); $totalY = $plotBottom - ($plotHeight * (int) $day['total'] / $chartMax); $blockedY = $plotBottom - ($plotHeight * (int) $day['blocked'] / $chartMax); $dayTimestamp = strtotime($day['date']); $dayLabel = $dayTimestamp ? $weekdaysFr[(int) gmdate('w', $dayTimestamp)] . ' ' . (int) gmdate('j', $dayTimestamp) . ' ' . $monthsFr[(int) gmdate('n', $dayTimestamp) - 1] : ''; ?>
              <circle class="chart-point chart-point-total" cx="<?= number_format($x, 1, '.', '') ?>" cy="<?= number_format($totalY, 1, '.', '') ?>" r="4"></circle>
              <circle class="chart-point chart-point-blocked" cx="<?= number_format($x, 1, '.', '') ?>" cy="<?= number_format($blockedY, 1, '.', '') ?>" r="3"></circle>
              <text class="chart-date-label" x="<?= number_format($x, 1, '.', '') ?>" y="222" text-anchor="middle"><?= console_escape($dayLabel) ?></text>
            <?php endforeach; ?>
          </svg>
        </div>
        <p class="chart-footnote">Les événements décrivent le trafic de l’application qui a été consigné localement.</p>
      </section>

      <div class="overview-rail">
        <section class="card decision-panel" aria-labelledby="decision-title">
          <div class="card-head"><div><p class="eyebrow">RÉPARTITION</p><h2 id="decision-title">Décisions du filtre</h2></div></div>
          <div class="decision-total"><strong><?= number_format($totalEvents, 0, ',', ' ') ?></strong><span>événements consignés</span></div>
          <div class="decision-list">
            <?php foreach ([['Bloquées', (int) $stats['blocked'], 'blocked'], ['Observées', (int) $stats['monitored'], 'watched'], ['Autorisées', (int) $stats['allowed'], 'allowed']] as [$label, $value, $tone]): $share = min(100, 100 * $value / $decisionDenominator); ?>
              <div class="decision-row">
                <div class="decision-row-head"><span><i class="decision-dot <?= $tone ?>" aria-hidden="true"></i><?= $label ?></span><strong><?= number_format($value, 0, ',', ' ') ?></strong></div>
                <div class="decision-track" role="img" aria-label="<?= $label ?> : <?= $value ?> sur <?= $totalEvents ?>"><span class="<?= $tone ?>" style="width:<?= number_format($share, 2, '.', '') ?>%"></span></div>
              </div>
            <?php endforeach; ?>
          </div>
          <?php if ($topType !== null): ?>
            <div class="top-signal"><span class="top-signal-label">Signal le plus fréquent</span><strong><?= console_escape((string) $topType) ?></strong><span><?= number_format((int) $stats['by_type'][$topType], 0, ',', ' ') ?> occurrence(s) consignée(s)</span></div>
          <?php else: ?>
            <div class="top-signal"><span class="top-signal-label">Signal le plus fréquent</span><strong>Aucun signal</strong><span>Les événements apparaîtront après les premiers tests.</span></div>
          <?php endif; ?>
        </section>

        <section class="engine-panel" aria-labelledby="engine-title">
          <div class="engine-heading"><span class="engine-indicator <?= $healthReady ? 'is-ready' : 'is-down' ?>" aria-hidden="true"></span><div><p class="eyebrow">ANALYSE LOCALE</p><h2 id="engine-title">État du modèle</h2></div></div>
          <p class="engine-state"><?= $healthReady ? 'MLP disponible' : 'MLP indisponible' ?></p>
          <p class="engine-copy"><?= $healthReady ? 'Le modèle local est prêt pour les cas ambigus.' : 'Le filtre par règles reste actif. Démarre le service MLP pour analyser les cas ambigus.' ?></p>
          <?php if (!empty($health['model_version'])): ?><p class="engine-version">Version <?= console_escape($health['model_version']) ?><?php if (($health['dataset_source'] ?? '') === 'synthetic_demo'): ?> · entraînement sur corpus synthétique de démonstration<?php endif; ?></p><?php endif; ?>
          <a class="engine-link" href="lab.php">Tester le filtre <span aria-hidden="true">→</span></a>
        </section>
      </div>
    </div>

    <section class="card incident-panel" id="incidents" aria-labelledby="incidents-title">
      <div class="incident-heading">
        <div><p class="eyebrow">JOURNAL LOCAL</p><h2 id="incidents-title">Événements récents</h2><p class="sub">Ouvre un événement pour lire son explication et sa référence.</p></div>
        <div class="export-actions">
          <a class="button secondary" href="<?= console_escape($exportBase . 'export=csv') ?>">Exporter CSV</a>
          <a class="button secondary" href="<?= console_escape($exportBase . 'export=jsonl') ?>">JSONL / SIEM</a>
        </div>
      </div>

      <form class="incident-filters" method="get" action="dashboard.php#incidents">
        <div class="filter-primary">
          <label class="filter-label" for="filter-action">Décision
            <select id="filter-action" name="action">
              <option value="">Toutes</option>
              <?php foreach (['BLOCKED' => 'Bloquées', 'BLOCKED_BY_AI' => 'Bloquées par IA', 'ALLOWED' => 'Autorisées', 'MONITORED' => 'Observées'] as $value => $label): ?>
                <option value="<?= console_escape($value) ?>" <?= $filters['action'] === $value ? 'selected' : '' ?>><?= $label ?></option>
              <?php endforeach; ?>
            </select>
          </label>
          <input type="hidden" name="search" value="<?= console_escape($filters['search']) ?>">
          <button class="button filter-submit" type="submit">Appliquer</button>
          <a class="button secondary" href="dashboard.php#incidents">Effacer les filtres</a>
          <details class="advanced-filters" <?= ($filters['type'] !== '' || $filters['from'] !== '' || $filters['to'] !== '') ? 'open' : '' ?>>
            <summary>Filtres avancés</summary>
            <div class="advanced-filter-fields">
              <label class="filter-label" for="filter-type">Type de signal
                <select id="filter-type" name="type"><option value="">Tous les types</option><?php foreach ($types as $type): ?><option value="<?= console_escape($type) ?>" <?= $filters['type'] === $type ? 'selected' : '' ?>><?= console_escape($type) ?></option><?php endforeach; ?></select>
              </label>
              <label class="filter-label" for="filter-from">À partir du<input id="filter-from" type="date" name="from" value="<?= console_escape($filters['from']) ?>"></label>
              <label class="filter-label" for="filter-to">Jusqu’au<input id="filter-to" type="date" name="to" value="<?= console_escape($filters['to']) ?>"></label>
            </div>
          </details>
        </div>
      </form>

      <div class="results-summary" aria-live="polite">
        <span><?= count($events) ?> événement(s) affiché(s) · page <?= $page ?></span>
        <?php if ($filters['search'] !== '' || $filters['action'] !== '' || $filters['type'] !== '' || $filters['from'] !== '' || $filters['to'] !== ''): ?><span>Filtres actifs · <a href="dashboard.php#incidents">Tout effacer</a></span><?php endif; ?>
      </div>

      <?php if (!$events): ?>
        <div class="empty-state" role="status"><span class="empty-icon" aria-hidden="true">⌕</span><h3>Aucun événement trouvé</h3><p>Essaie une autre recherche ou retire un filtre. La saisie de recherche reste affichée en haut de page.</p></div>
      <?php else: ?>
        <div class="incident-list">
          <?php foreach ($events as $event): $explanation = console_explanation($event); $action = (string) ($event['action'] ?? 'ALLOWED'); $rawType = (string) ($event['attack_type'] ?? 'NONE'); $attackType = $rawType === 'NONE' ? 'Requête sans signal' : $rawType; $timestamp = strtotime((string) ($event['timestamp'] ?? '')); $sourceRaw = strtolower((string) ($event['source'] ?? 'heuristic')); $sourceLabel = match ($sourceRaw) { 'ai', 'mlp' => 'Modèle MLP', 'heuristic' => 'Règles locales', 'ip_policy' => 'Règle d’accès IP', default => ucfirst($sourceRaw) }; ?>
            <details class="incident-row">
              <summary class="incident-summary">
                <span class="incident-decision"><span class="pill <?= console_action_class($action) ?>"><?= console_escape(console_action_label($action)) ?></span></span>
                <span class="incident-main"><strong><?= console_escape($attackType) ?></strong><span class="incident-route"><span class="mono"><?= console_escape($event['method'] ?? '—') ?></span> <?= console_escape($event['path'] ?? '/') ?></span></span>
                <span class="incident-meta"><time <?= $timestamp ? 'datetime="' . console_escape(date('c', $timestamp)) . '"' : '' ?>><?= $timestamp ? console_escape(date('d/m/Y H:i', $timestamp)) : 'Date inconnue' ?></time><span>IP <?= console_escape($event['ip'] ?? 'inconnue') ?></span></span>
                <span class="incident-open">Détails <span aria-hidden="true">＋</span></span>
              </summary>
              <div class="incident-details">
                <div class="incident-facts">
                  <div><span>Risque heuristique</span><strong><?= (int) ($event['score'] ?? 0) ?>/100</strong></div>
                  <div><span>Décision prise par</span><strong><?= console_escape($sourceLabel) ?></strong></div>
                  <div><span>Analyse MLP</span><strong><?= isset($event['risk']) ? number_format((float) $event['risk'] * 100, 1, ',', ' ') . ' %' : 'Non sollicitée' ?></strong></div>
                  <div><span>Temps de traitement</span><strong><?= console_escape($event['latency_ms'] ?? 0) ?> ms</strong></div>
                </div>
                <p class="incident-reason"><?= console_escape($event['reason'] ?? 'Aucune explication enregistrée.') ?></p>
                <?php if (!empty($event['model_version'])): ?><p class="incident-model">Modèle : <?= console_escape($event['model_version']) ?></p><?php endif; ?>
                <div class="explanation"><strong><?= console_escape($explanation['label']) ?></strong><p><?= console_escape($explanation['what']) ?></p><p><?= console_escape($explanation['advice']) ?></p></div>
                <p class="incident-reference">Référence <code><?= console_escape($event['id'] ?? '') ?></code></p>
              </div>
            </details>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>
      <?php if ($events || $page > 1): ?>
        <nav class="journal-pagination" aria-label="Pagination des événements">
          <span>Page <?= $page ?><?= $hasNextPage ? ' · d’autres événements sont disponibles' : '' ?></span>
          <div>
            <?php if ($page > 1): ?><a class="button secondary" href="<?= console_escape($paginationBase . 'page=' . ($page - 1) . '#incidents') ?>">Précédente</a><?php endif; ?>
            <?php if ($hasNextPage): ?><a class="button secondary" href="<?= console_escape($paginationBase . 'page=' . ($page + 1) . '#incidents') ?>">Suivante</a><?php endif; ?>
          </div>
        </nav>
      <?php endif; ?>
      <p class="journal-note">Les traces sont conservées localement. Les saisies brutes et les données sensibles sont masquées.</p>
    </section>

    <footer class="dashboard-footer"><a href="../index.php">Retour à l’accueil</a><span>Les nombres affichés proviennent des événements conservés localement.</span></footer>
  </main>
</div>
</body>
</html>
