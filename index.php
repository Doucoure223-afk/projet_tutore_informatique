<?php
require_once __DIR__ . '/security/bootstrap.php';
require_once __DIR__ . '/security/ia_analyzer.php';
require_once __DIR__ . '/security/access.php';
require_once __DIR__ . '/app/LocalSetupAccess.php';
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; base-uri 'self'; frame-ancestors 'none'");
header('Cache-Control: no-store');
$health = console_health();
$localOnly = cybershield_local_request_allowed($_SERVER);
?><!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#f1efe8"><title>CyberShield AI · Analyse des requêtes SQL</title><link rel="stylesheet" href="security/console.css?v=<?= (int) filemtime(__DIR__ . '/security/console.css') ?>"></head>
<body><main class="home">
  <a class="brand" href="index.php"><span class="brand-mark">C<span>◆</span></span><span>CyberShield <b>AI</b><small>PROTECTION SQLi · DÉMONSTRATION LOCALE</small></span></a>
  <section class="home-hero"><p class="eyebrow">CYBERSÉCURITÉ · BAMAKO</p><h1>Repérer les injections.<br><span style="color:var(--mint)">Comprendre la décision.</span></h1><p class="muted intro">Des règles et un modèle local pour analyser les saisies, avec des décisions consultables dans la console.</p></section>
  <nav class="pathways" aria-label="Accès au projet">
   <a class="pathway" href="security/dashboard.php"><span class="pathway-index">01</span><span class="pathway-copy"><span class="eyebrow">SUPERVISION</span><strong>Consulter la console</strong><small>Événements, décisions du filtre et état du modèle.</small></span><span class="badge <?=!empty($health['model_loaded'])?'ok':'warn'?> pathway-status"><span class="dot"></span> MLP <?=!empty($health['model_loaded'])?'disponible':'à démarrer'?></span><span class="pathway-arrow" aria-hidden="true">→</span></a>
   <a class="pathway" href="security/lab.php"><span class="pathway-index">02</span><span class="pathway-copy"><span class="eyebrow">ANALYSE</span><strong>Tester une saisie</strong><small>Comparer des entrées sans exécuter de requête SQL.</small></span><span class="badge pathway-status">Aucune écriture dans la base</span><span class="pathway-arrow" aria-hidden="true">→</span></a>
   <a class="pathway" href="app/search.php"><span class="pathway-index">03</span><span class="pathway-copy"><span class="eyebrow">APPLICATION</span><strong>Parcourir la boutique</strong><small>Catalogue, panier et suivi des commandes.</small></span><span class="badge ok pathway-status">Requêtes préparées · CSRF actif</span><span class="pathway-arrow" aria-hidden="true">→</span></a>
  </nav>
  <?php if(!$localOnly):?><p class="home-access-note">La supervision nécessite un accès administrateur.</p><?php endif;?>
  <footer class="muted">Équipe CyberShield AI · Sékou Doucouré et Hawa Thiama</footer>
</main></body></html>
