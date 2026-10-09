<?php
require_once __DIR__ . '/assistant-client.php';

console_require_access();

$answer = '';
$error = '';
$question = '';
$health = cybershield_assistant_health();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    console_check_csrf();
    $question = trim(is_string($_POST['question'] ?? null) ? $_POST['question'] : '');
    $result = cybershield_assistant_ask($question, 'assistant');
    if (!empty($result['ok'])) {
        $answer = (string) $result['answer'];
    } else {
        $error = (string) ($result['error'] ?? 'Le modèle local est indisponible.');
    }
}

$csrf = console_csrf();
$modelName = preg_match('/^[A-Za-z0-9._:-]{1,80}$/D', (string) ($health['model'] ?? '')) ? (string) $health['model'] : 'modèle local';
?>
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="theme-color" content="#f1efe8">
  <title>Assistant IA · CyberShield AI</title>
  <link rel="stylesheet" href="console.css?v=<?= (int) filemtime(__DIR__ . '/console.css') ?>">
</head>
<body>
<a class="skip-link" href="#main-content">Aller au contenu</a>
<div class="shell dashboard-shell">
  <?php console_sidebar('assistant'); ?>
  <main class="main" id="main-content">
    <header class="dashboard-toolbar">
      <nav class="breadcrumbs" aria-label="Fil d’Ariane"><a href="dashboard.php">Supervision</a><span aria-hidden="true">/</span><span aria-current="page">Assistant IA</span></nav>
      <a class="button secondary toolbar-action" href="dashboard.php">Retour à la supervision</a>
    </header>

    <section class="page-heading" aria-labelledby="page-title">
      <div><p class="eyebrow">CYBERSHIELD AI <span class="eyebrow-divider">/</span> TRIAGE ASSISTÉ</p><h1 id="page-title">Assistant de sécurité</h1><p class="muted">Pose une question sur l’état du filtre ou les derniers signaux consignés.</p></div>
      <div class="assistant-status <?= !empty($health['available']) ? 'is-ready' : 'is-down' ?>" role="status"><span class="engine-indicator <?= !empty($health['available']) ? 'is-ready' : 'is-down' ?>"></span><?= !empty($health['available']) ? 'Modèle local prêt' : 'Modèle local indisponible' ?></div>
    </section>

    <?php if ($error !== ''): ?><div class="callout warn" role="alert"><strong>Réponse non générée.</strong><p><?= console_escape($error) ?></p></div><?php endif; ?>

    <div class="assistant-layout">
      <section class="card assistant-composer" aria-labelledby="assistant-form-title">
        <div class="card-head"><div><p class="eyebrow">QUESTION</p><h2 id="assistant-form-title">Que veux-tu comprendre&nbsp;?</h2></div><span class="assistant-model-label"><?= console_escape($modelName) ?> · LangGraph</span></div>
        <form method="post" action="assistant.php" class="assistant-form">
          <input type="hidden" name="csrf_token" value="<?= console_escape($csrf) ?>">
          <label for="assistant-question">Question sur le filtre, les compteurs ou les signaux récents</label>
          <textarea id="assistant-question" name="question" rows="5" maxlength="1200" required placeholder="Ex. Pourquoi certaines requêtes sont observées plutôt que bloquées ?"><?= console_escape($question) ?></textarea>
          <div class="assistant-form-footer"><span>1 200 caractères maximum</span><button class="button" type="submit" <?= empty($health['available']) ? 'aria-describedby="assistant-offline-note"' : '' ?>>Analyser avec l’assistant <span aria-hidden="true">→</span></button></div>
        </form>
        <?php if (empty($health['available'])): ?><p id="assistant-offline-note" class="assistant-help">Pour l’activer, démarre le service LangGraph et Ollama, puis installe le modèle local configuré. Le filtre SQLi fonctionne indépendamment de cet assistant.</p><?php endif; ?>
      </section>

      <aside class="card assistant-boundary" aria-labelledby="assistant-boundary-title">
        <p class="eyebrow">CONFIDENTIALITÉ</p><h2 id="assistant-boundary-title">Lecture seule. Données limitées.</h2>
        <p class="assistant-boundary-intro">La question est envoyée au modèle local. N’y ajoute aucun secret ni renseignement personnel.</p>
        <details class="assistant-details"><summary>Quelles données et quelles limites&nbsp;?</summary>
          <ul>
            <li>Le modèle fonctionne localement avec Ollama.</li>
            <li>Le contexte ne contient que des compteurs et jusqu’à huit catégories d’événements.</li>
            <li>Les adresses IP, routes, formulaires et payloads des journaux ne sont pas transmis.</li>
            <li>La conversation n’est pas conservée après la réponse.</li>
            <li>L’assistant ne peut ni modifier le filtre ni exécuter du SQL.</li>
          </ul>
        </details>
        <p class="assistant-caution">Vérifie les réponses dans le code et les journaux autorisés avant d’agir.</p>
      </aside>
    </div>

    <?php if ($answer !== ''): ?>
      <section class="card assistant-answer-card" aria-labelledby="assistant-answer-title" aria-live="polite">
        <div class="card-head"><div><p class="eyebrow">RÉPONSE DU MODÈLE LOCAL</p><h2 id="assistant-answer-title">Analyse proposée</h2></div><span class="pill pill-allow">Lecture seule</span></div>
        <pre class="assistant-answer"><?= console_escape($answer) ?></pre>
        <p class="assistant-help">Cette réponse aide à interpréter le tableau de bord; elle ne constitue pas une décision de sécurité ni un audit.</p>
      </section>
    <?php endif; ?>

    <footer class="dashboard-footer"><a href="dashboard.php">Retour à la supervision</a><span>Les décisions du filtre restent déterministes et indépendantes du LLM.</span></footer>
  </main>
</div>
</body>
</html>
