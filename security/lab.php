<?php
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/ia_analyzer.php';
require_once __DIR__ . '/access.php';
require_once __DIR__ . '/hybrid_analyzer.php';
console_require_access();
$result = null;
$value = "admin' --";
$context = 'login';
$error = '';
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    console_check_csrf();
    $value = is_string($_POST['payload'] ?? null) ? substr($_POST['payload'], 0, 8192) : '';
    $context = in_array($_POST['context'] ?? '', ['login', 'search', 'register', 'admin'], true) ? $_POST['context'] : 'search';
    try {
        $result = (new HybridAnalyzer())->analyze($value, 'laboratoire', $context);
    } catch (Throwable $e) {
        $error = 'Analyse indisponible. Consultez l’état du service sur la page de supervision.';
    }
}
$health = console_health();
?>
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#0a1018"><title>Laboratoire · CyberShield AI</title><link rel="stylesheet" href="console.css"></head>
<body><div class="shell"><?php console_sidebar('lab'); ?><main class="main">
  <div class="topline"><div class="headline"><p class="eyebrow">LABORATOIRE · ANALYSE SANS EXÉCUTION</p><h1>Étudier une saisie</h1><p class="muted">Le laboratoire calcule une décision. Il ne transmet la saisie à aucune requête SQL et ne l’ajoute pas au journal des incidents.</p></div><span class="badge <?=!empty($health['model_loaded'])?'ok':'warn'?>"><span class="dot"></span>MLP <?=!empty($health['model_loaded'])?'disponible':'indisponible'?></span></div>
  <div class="grid"><section class="card"><div class="card-head"><div><h2>Nouvelle analyse</h2><p class="sub">Heuristique rapide, puis MLP seulement dans la zone grise.</p></div></div>
    <form method="post" action="lab.php"><input type="hidden" name="csrf_token" value="<?=console_escape(console_csrf())?>"><div class="field"><label for="payload">Texte à analyser</label><textarea id="payload" name="payload" maxlength="8192" required><?=console_escape($value)?></textarea></div>
      <div class="field"><label for="context">Contexte du champ</label><select id="context" name="context"><?php foreach(['login'=>'Connexion','search'=>'Recherche','register'=>'Inscription','admin'=>'Administration'] as $key=>$label):?><option value="<?=$key?>" <?=$context===$key?'selected':''?>><?=$label?></option><?php endforeach;?></select></div>
      <p class="event-detail">À essayer : <code>' OR '1'='1' --</code> · <code>admin' --</code> · <code>Clavier mécanique</code> · <code>Bonjour -- merci</code></p>
      <button class="button" type="submit">Analyser localement →</button>
    </form></section>
    <section class="card"><div class="card-head"><div><h2>Déroulement</h2><p class="sub">Trois décisions, une défense complémentaire.</p></div></div>
      <div class="event"><strong>01 · Normaliser et scorer</strong><p class="event-detail">Les motifs SQL connus reçoivent un score sur 100. Les signatures franches coupent le traitement immédiatement.</p></div>
      <div class="event"><strong>02 · Examiner la zone grise</strong><p class="event-detail">Les scores intermédiaires sont envoyés au MLP local ; le seuil de décision est 0,75.</p></div>
      <div class="event"><strong>03 · Préparer les requêtes</strong><p class="event-detail">Le filtre ne remplace pas les paramètres liés, qui restent obligatoires côté application.</p></div>
      <div class="callout <?=empty($health['model_loaded'])?'warn':''?>"><?=empty($health['model_loaded'])?'Si le MLP est arrêté, une saisie ambiguë est bloquée par précaution.':'Le modèle local répond. Son jeu synthétique sert à la démonstration, pas à prouver les résultats du dossier initial.'?></div>
    </section></div>
  <?php if($error):?><div class="callout danger" role="alert"><?=console_escape($error)?></div><?php endif;?>
  <?php if($result):$blocked=(bool)$result['would_block'];?><section class="card" style="margin-top:16px"><div class="card-head"><div><p class="eyebrow">RÉSULTAT</p><h2><?= $blocked?'À bloquer':'Peut être autorisé par le filtre' ?></h2><p class="sub"><?=console_escape($result['reason'])?></p></div><span class="pill <?=$blocked?'danger':'success'?>"><?=$blocked?'BLOCAGE':'AUTORISATION'?></span></div>
    <div class="stats" style="margin:12px 0"><div class="stat"><div class="stat-label">Score heuristique</div><div class="stat-value"><?= (int)$result['score'] ?><small style="font-size:13px;color:var(--muted)"> / 100</small></div></div><div class="stat"><div class="stat-label">Source de la décision</div><div class="stat-value" style="font-size:20px"><?=console_escape($result['source'])?></div></div><div class="stat"><div class="stat-label">Score MLP</div><div class="stat-value" style="font-size:20px"><?=isset($result['risk'])?number_format((float)$result['risk']*100,1,',',' ').' %':'—'?></div></div><div class="stat"><div class="stat-label">Type estimé</div><div class="stat-value" style="font-size:17px"><?=console_escape($result['attack_type'])?></div></div></div>
    <p class="event-detail">Règles : <?=console_escape(implode(', ',array_map('strval',$result['patterns'])))?:'aucune signature'?> · IA : <?=console_escape($result['ai_status'])?><?php if($result['model_version']):?> · modèle <?=console_escape($result['model_version'])?><?php endif;?> · <?=console_escape($result['latency_ms'])?> ms</p>
    <?php $explanation=console_explanation($result);?><div class="explanation"><strong>Guide local</strong><div><?=console_escape($explanation['what'])?></div><div><?=console_escape($explanation['advice'])?></div></div><p class="muted" style="font-size:11px">Le score de confiance du modèle n’est pas calibré. Ce résultat d’enseignement ne certifie pas l’innocuité d’une saisie.</p>
  </section><?php endif;?>
</main></div></body></html>
