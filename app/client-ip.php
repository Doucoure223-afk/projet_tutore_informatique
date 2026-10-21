<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/store_layout.php';
$clientIp = cybershield_client_ip();
$user = current_user();
header('Cache-Control: no-store');
?>
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cet appareil · CyberShield AI</title><link rel="stylesheet" href="store.css?v=<?= (int) filemtime(__DIR__ . '/store.css') ?>"><link rel="stylesheet" href="checkout.css?v=<?= (int) filemtime(__DIR__ . '/checkout.css') ?>"></head><body class="store-page"><?php store_header('catalogue', $user); ?><main class="store-main" id="main-content"><section class="cart-empty"><div class="cart-empty-art"><?= store_icon('check') ?></div><p class="store-eyebrow">ACCÈS À LA BOUTIQUE</p><h1>Cet appareil est connecté.</h1><p>Adresse reconnue pour cet appareil :<br><strong class="device-address" style="font-size:1.7rem;color:var(--store-accent)"><?= escape_output($clientIp) ?></strong></p><p>Cette adresse apparaît dans la console. Pendant la démonstration, l’administrateur peut bloquer puis rétablir l’accès de cet appareil.</p><a class="store-button store-button--primary" href="search.php">Ouvrir le catalogue <?= store_icon('arrow') ?></a></section></main><?php store_footer(); ?></body></html>
