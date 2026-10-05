<?php
/** Deterministic explanations. This guide never calls an LLM. */
function console_explanation(array $event): array
{
    $patterns = is_array($event['patterns'] ?? null) ? $event['patterns'] : [];
    $type = strtoupper((string) ($event['attack_type'] ?? $event['type'] ?? 'NONE'));
    $rules = implode(' ', array_map(function ($value) { return is_scalar($value) ? (string) $value : ''; }, $patterns));
    $signature = $type . ' ' . $rules;
    if (strpos($signature, 'UNION') !== false) {
        $what = 'La saisie contient une structure UNION SELECT, qui peut joindre les résultats d’une requête supplémentaire à ceux attendus.';
        $advice = 'Conservez la structure SQL côté serveur et transmettez les valeurs au moyen de paramètres liés. Limitez aussi les droits du compte de base de données.';
    } elseif (preg_match('/TIME|SLEEP|BENCHMARK|WAITFOR/', $signature)) {
        $what = 'Une instruction de temporisation SQL a été repérée. Ce procédé peut révéler des informations en comparant les temps de réponse.';
        $advice = 'Utilisez les requêtes préparées, des délais d’exécution bornés et examinez les répétitions provenant de la même origine.';
    } elseif (preg_match('/BOOLEAN|TAUTOLOGY|NUMERIC/', $signature)) {
        $what = 'Une comparaison reliée par OR ou AND peut modifier la condition d’une requête, notamment lors d’une authentification.';
        $advice = 'Séparez les données du texte SQL, vérifiez le mot de passe avec password_verify et refusez toute authentification fondée sur une requête concaténée.';
    } elseif (preg_match('/COMMENT/', $signature)) {
        $what = 'Une apostrophe suivie d’un commentaire SQL peut neutraliser la fin d’une requête. Cette signature relève de la zone grise du moteur.';
        $advice = 'Vérifiez le contexte du champ et la décision du modèle. La requête préparée reste la protection de référence, même si le filtre autorise la saisie.';
    } elseif (preg_match('/STACKED|DESTRUCTIVE|WRITE_STATEMENT/', $signature)) {
        $what = 'Une instruction SQL supplémentaire ou une opération d’écriture apparaît dans la saisie.';
        $advice = 'N’exécutez pas de requêtes multiples issues d’une entrée utilisateur. Utilisez des paramètres liés et des permissions minimales en base.';
    } elseif (preg_match('/ERROR|FILE_ACCESS|SYSTEM_CATALOG/', $signature)) {
        $what = 'La saisie fait référence à une fonction SQL, un fichier ou un catalogue système susceptible d’exposer des informations internes.';
        $advice = 'Gardez les erreurs techniques dans des journaux privés et limitez les droits de lecture, d’écriture et d’accès aux fichiers du compte SQL.';
    } elseif (($event['score'] ?? 0) < 30 && !($event['block'] ?? false) && in_array($type, ['NONE', 'NORMAL', 'LOW_RISK', ''], true)) {
        $what = 'Aucune signature SQLi significative n’a été reconnue dans cette saisie par les règles locales.';
        $advice = 'Une autorisation du filtre n’est pas une garantie d’innocuité. L’application doit toujours utiliser des requêtes préparées et valider ses données.';
    } else {
        $what = 'Cette saisie combine des indices qui nécessitent une décision contextualisée. Consultez la source, les signatures et le motif enregistrés.';
        $advice = 'Vérifiez les données du champ et les journaux associés. Faites évoluer les règles avec des exemples légitimes et malveillants avant de modifier un seuil.';
    }
    if (in_array(strtolower((string) ($event['ai_status'] ?? '')), ['unavailable', 'error', 'timeout', 'degraded', 'model_unavailable'], true)) {
        $advice .= ' Le service IA est indisponible : la décision affichée doit être interprétée selon le mode de repli indiqué.';
    }
    return ['what' => $what, 'advice' => $advice, 'label' => 'Guide local'];
}

function console_action_label(string $action): string
{
    return ['BLOCKED' => 'Bloquée', 'BLOCKED_BY_AI' => 'Bloquée par IA', 'ALLOWED' => 'Autorisée', 'MONITORED' => 'Observée'][$action] ?? $action;
}

function console_action_class(string $action): string
{
    return in_array($action, ['BLOCKED', 'BLOCKED_BY_AI'], true) ? 'danger' : ($action === 'MONITORED' ? 'warning' : 'success');
}
