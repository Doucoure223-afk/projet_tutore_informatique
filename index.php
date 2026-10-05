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
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#0a1018"><title>CyberShield AI · Détecter, comprendre, protéger</title><link rel="stylesheet" href="security/console.css"></head>
<body><main class="main" style="max-width:1100px;margin:0 auto;padding-top:8vh">
  <a class="brand" href="index.php"><span class="brand-mark">C<span>◆</span></span><span>CyberShield <b>AI</b><small>PROTECTION SQLi · DÉMONSTRATION LOCALE</small></span></a>
  <section style="padding:clamp(34px,8vw,92px) 0 35px;max-width:840px"><p class="eyebrow">ÉCOLE NATIONALE D’INGÉNIEURS · BAMAKO</p><h1 style="font-size:clamp(42px,7vw,76px);letter-spacing:-.06em">La sécurité qui sait <span style="color:var(--mint)">expliquer.</span></h1><p class="muted" style="font-size:18px;max-width:690px">Un MVP local qui analyse les injections SQL par règles, examine les cas ambigus avec un MLP et protège la base avec des requêtes préparées.</p></section>
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(250px,1fr))">
   <a class="card" href="security/dashboard.php"><p class="eyebrow">01 · SUPERVISION</p><h2>Console de sécurité →</h2><p class="muted">Statistiques réelles, journal filtrable et explications en langage simple.</p><span class="badge <?=!empty($health['model_loaded'])?'ok':'warn'?>"><span class="dot"></span> MLP <?=!empty($health['model_loaded'])?'disponible':'à démarrer'?></span></a>
   <a class="card" href="security/lab.php"><p class="eyebrow">02 · ANALYSE</p><h2>Laboratoire SQLi →</h2><p class="muted">Comparez des saisies sans exécuter de SQL et voyez le raisonnement du moteur.</p><span class="badge">Aucune requête de test n’atteint la base</span></a>
   <a class="card" href="app/search.php"><p class="eyebrow">03 · APPLICATION</p><h2>Boutique pédagogique →</h2><p class="muted">Parcourez le catalogue, créez un compte et réalisez un achat explicitement simulé.</p><span class="badge ok">SQL préparé · CSRF actif</span></a>
  </div>
  <?php if(!$localOnly):?><p class="callout warn" style="margin-top:18px">La supervision et le laboratoire sont réservés à la machine locale ou à un administrateur authentifié.</p><?php endif;?>
  <footer class="muted" style="font-size:11px;margin-top:35px">Sékou Doucouré · Adama Nakoun Fané · ENI-ABT, Bamako · Démonstration locale</footer>
</main></body></html>
