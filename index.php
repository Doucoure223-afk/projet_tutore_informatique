<?php
require_once __DIR__ . '/security/ia_analyzer.php';
require_once __DIR__ . '/security/access.php';
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; base-uri 'self'; frame-ancestors 'none'");
header('Cache-Control: no-store');
$health = console_health();
$localOnly = in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1','::1','::ffff:127.0.0.1'], true);
?><!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#f1efe8"><title>CyberShield AI · Analyse des requêtes SQL</title><link rel="stylesheet" href="security/console.css"></head>
<body><main class="home">
  <a class="brand" href="index.php"><span class="brand-mark">C<span>◆</span></span><span>CyberShield <b>AI</b><small>PROTECTION SQLi · DÉMONSTRATION LOCALE</small></span></a>
  <section class="home-hero"><p class="eyebrow">ÉCOLE NATIONALE D’INGÉNIEURS · BAMAKO</p><h1>Repérer les injections.<br><span style="color:var(--mint)">Comprendre la décision.</span></h1><p class="muted intro">CyberShield AI analyse les requêtes SQL par règles, examine localement certains cas ambigus avec un MLP et protège la base grâce aux requêtes préparées.</p></section>
  <nav class="pathways" aria-label="Accès au projet">
   <a class="pathway" href="security/dashboard.php"><span class="pathway-index">01</span><span class="pathway-copy"><span class="eyebrow">SUPERVISION</span><strong>Consulter la console</strong><small>Événements, décisions du filtre et état du modèle.</small></span><span class="badge <?=!empty($health['model_loaded'])?'ok':'warn'?> pathway-status"><span class="dot"></span> MLP <?=!empty($health['model_loaded'])?'disponible':'à démarrer'?></span><span class="pathway-arrow" aria-hidden="true">→</span></a>
   <a class="pathway" href="security/lab.php"><span class="pathway-index">02</span><span class="pathway-copy"><span class="eyebrow">ANALYSE</span><strong>Tester une saisie</strong><small>Comparer des entrées sans exécuter de requête SQL.</small></span><span class="badge pathway-status">Aucune écriture dans la base</span><span class="pathway-arrow" aria-hidden="true">→</span></a>
   <a class="pathway" href="app/search.php"><span class="pathway-index">03</span><span class="pathway-copy"><span class="eyebrow">APPLICATION</span><strong>Parcourir la boutique</strong><small>Catalogue, panier et parcours d’achat simulé.</small></span><span class="badge ok pathway-status">Requêtes préparées · CSRF actif</span><span class="pathway-arrow" aria-hidden="true">→</span></a>
  </nav>
  <?php if(!$localOnly):?><p class="callout warn" style="margin-top:18px">La supervision et le laboratoire sont réservés à la machine locale ou à un administrateur authentifié.</p><?php endif;?>
  <footer class="muted">Sékou Doucouré · Adama Nakoun Fané · ENI-ABT, Bamako · Démonstration locale</footer>
</main></body></html>
