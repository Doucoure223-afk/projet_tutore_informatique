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
$events = $logger->getEvents($filters, 100);
$maxBars = 1;
foreach ($daily as $day) { $maxBars = max($maxBars, $day['total']); }
$healthReady = !empty($health['model_loaded']);
$types = array_keys($stats['by_type']);
?>
<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0a1018"><title>Supervision · CyberShield AI</title><link rel="stylesheet" href="console.css"></head>
<body><div class="shell">
<?php console_sidebar('dashboard'); ?>
<main class="main">
  <div class="topline"><div class="headline"><p class="eyebrow">SUPERVISION · 7 DERNIERS JOURS</p><h1>Protection en temps réel</h1><p class="muted">Décisions du middleware et incidents enregistrés par CyberShield AI.</p></div>
    <span class="badge <?= $healthReady ? 'ok' : 'warn' ?>"><span class="dot"></span> MLP <?= $healthReady ? 'opérationnel' : 'indisponible' ?></span></div>
  <?php if (!$healthReady): ?><div class="callout warn">Le service IA ou son modèle n’est pas disponible. Les cas ambigus sont bloqués par précaution. Lancez l’installation, l’entraînement et le service local depuis le guide du projet.</div><?php endif; ?>
  <?php if (($health['dataset_source'] ?? '') === 'synthetic_demo'): ?><p class="muted" style="font-size:11px;margin:9px 0">Modèle <?= console_escape($health['model_version'] ?? '') ?> · corpus synthétique de démonstration</p><?php endif; ?>
  <section class="stats" aria-label="Indicateurs de sécurité">
    <div class="stat"><div class="stat-label">Requêtes analysées</div><div class="stat-value"><?= (int) $stats['total'] ?></div><div class="stat-foot">sur les 7 derniers jours</div></div>
    <div class="stat"><div class="stat-label">Incidents identifiés</div><div class="stat-value"><?= (int) $stats['attacks'] ?></div><div class="stat-foot">risque élevé ou à examiner</div></div>
    <div class="stat"><div class="stat-label">Bloquées</div><div class="stat-value" style="color:var(--red)"><?= (int) $stats['blocked'] ?></div><div class="stat-foot"><?= console_escape((string) $stats['block_rate']) ?> % des requêtes</div></div>
    <div class="stat"><div class="stat-label">Transmises au MLP</div><div class="stat-value" style="color:var(--mint)"><?= (int) $stats['ai_analyzed'] ?></div><div class="stat-foot">appels réellement journalisés</div></div>
  </section>
  <div class="grid">
    <section class="card"><div class="card-head"><div><h2>Activité quotidienne</h2><p class="sub">Comptages calculés depuis les événements JSONL.</p></div><span class="badge">7 jours</span></div>
      <div class="bars"><?php foreach ($daily as $day): $totalWidth = $day['total'] ? max(2, 100 * $day['total'] / $maxBars) : 0; $blockedWidth = $day['total'] ? 100 * $day['blocked'] / $day['total'] : 0; ?>
        <div class="bar-row"><span><?= console_escape(date('D d/m', strtotime($day['date']))) ?></span><div class="bar-track" title="<?= (int)$day['blocked'] ?> bloquées · <?= (int)$day['allowed'] ?> autorisées"><span class="bar-block" style="width:<?= round($totalWidth * $blockedWidth / 100, 2) ?>%"></span><span class="bar-allow" style="width:<?= round($totalWidth * (100 - $blockedWidth) / 100, 2) ?>%"></span></div><span class="bar-count"><?= (int)$day['total'] ?> <small>· <?= (int)$day['blocked'] ?> bloq.</small></span></div>
      <?php endforeach; ?></div><p class="sub">Rouge : bloquées · vert : autorisées ou observées.</p></section>
    <section class="card"><div class="card-head"><div><h2>Décision du filtre</h2><p class="sub">Les requêtes préparées protègent la base en complément.</p></div></div>
      <div class="event"><div class="event-top"><span class="pill danger">Bloquées</span><strong><?= (int)$stats['blocked'] ?></strong><span class="event-meta">heuristique ou MLP</span></div></div>
      <div class="event"><div class="event-top"><span class="pill success">Autorisées</span><strong><?= (int)$stats['allowed'] ?></strong><span class="event-meta">signature significative absente</span></div></div>
      <div class="event"><div class="event-top"><span class="pill warning">Observées</span><strong><?= (int)$stats['monitored'] ?></strong><span class="event-meta">mode d’observation</span></div></div>
      <div class="callout">Les indicateurs décrivent les événements conservés localement. Les résultats d’entraînement ne représentent pas le trafic réel.</div>
    </section>
  </div>
  <section class="card"><div class="card-head"><div><h2>Journal des incidents</h2><p class="sub">Jusqu’à 100 décisions finales, avec explication et source.</p></div><a class="button secondary" href="dashboard.php?<?= http_build_query(array_filter($filters, static fn($v) => $v !== '')) ?>&amp;export=csv">↓ Exporter en CSV</a></div>
    <form class="filters" method="get" action="dashboard.php">
      <label class="sr-only" for="f-action">Décision</label><select id="f-action" name="action"><option value="">Toutes les décisions</option><?php foreach (['BLOCKED'=>'Bloquée','BLOCKED_BY_AI'=>'Bloquée par IA','ALLOWED'=>'Autorisée','MONITORED'=>'Observée'] as $value=>$label): ?><option value="<?= $value ?>" <?= $filters['action']===$value?'selected':'' ?>><?= $label ?></option><?php endforeach; ?></select>
      <label class="sr-only" for="f-type">Type</label><select id="f-type" name="type"><option value="">Tous les types</option><?php foreach($types as $type): ?><option <?= $filters['type']===$type?'selected':'' ?> value="<?=console_escape($type)?>"><?=console_escape($type)?></option><?php endforeach; ?></select>
      <label class="sr-only" for="f-search">Rechercher</label><input id="f-search" name="search" placeholder="IP, route ou type" value="<?=console_escape($filters['search'])?>">
      <label class="sr-only" for="f-from">Depuis</label><input type="date" id="f-from" name="from" value="<?=console_escape($filters['from'])?>">
      <label class="sr-only" for="f-to">Jusqu’à</label><input type="date" id="f-to" name="to" value="<?=console_escape($filters['to'])?>">
      <button class="button" type="submit">Filtrer</button><a class="button secondary" href="dashboard.php">Effacer</a>
    </form>
    <?php if (!$events): ?><div class="empty">Aucun événement ne correspond à ces filtres.</div><?php else: ?>
    <?php foreach($events as $event): $explanation = console_explanation($event); $action = (string)($event['action'] ?? 'ALLOWED'); ?>
      <article class="event"><div class="event-top"><span class="pill <?=console_action_class($action)?>"><?=console_escape(console_action_label($action))?></span><strong><?=console_escape($event['attack_type'] ?? 'NONE')?></strong><span class="event-meta"><?=console_escape(date('d/m/Y H:i:s', strtotime($event['timestamp'])))?> · <?=console_escape($event['ip'])?> · <?=console_escape($event['method'])?> <?=console_escape($event['path'])?></span></div>
        <p class="event-detail">Risque heuristique <?= (int)($event['score']??0) ?>/100 · source <?=console_escape($event['source']??'heuristic')?><?php if(isset($event['risk'])): ?> · score MLP <?=number_format((float)$event['risk']*100,1,',',' ')?> %<?php endif; ?><?php if(!empty($event['model_version'])): ?> · <?=console_escape($event['model_version'])?><?php endif; ?> · <?=console_escape($event['latency_ms']??0)?> ms</p>
        <p class="event-detail"><?=console_escape($event['reason']??'')?></p><div class="explanation"><strong><?=console_escape($explanation['label'])?></strong><div><?=console_escape($explanation['what'])?></div><div><?=console_escape($explanation['advice'])?></div></div></article>
    <?php endforeach; ?><?php endif; ?>
  </section>
  <p class="muted" style="font-size:11px;margin-top:18px">Le « Guide local » est déterministe et fonctionne hors ligne ; aucune explication n’est envoyée à un service tiers.</p>
</main></div></body></html>
