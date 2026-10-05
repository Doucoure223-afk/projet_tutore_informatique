<?php
class ResponseHandler
{
    public static function blockRequest($attackType, $payload = '', $requestId = null, $statusCode = 403)
    {
        $incident = $requestId ?: bin2hex(random_bytes(8));
        http_response_code($statusCode);
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Cache-Control: no-store');
        header('Referrer-Policy: no-referrer');
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'");
        if (strpos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['error' => 'request_blocked', 'message' => 'Cette requête a été arrêtée par CyberShield AI.', 'incident_id' => $incident], JSON_UNESCAPED_UNICODE);
            exit;
        }
        header('Content-Type: text/html; charset=utf-8');
        $id = htmlspecialchars($incident, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        // Never reflect the intercepted payload, request headers or credentials.
        echo '<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Requête bloquée · CyberShield AI</title><style>';
        echo 'body{margin:0;min-height:100vh;display:grid;place-items:center;background:#101724;color:#eef3fa;font:16px/1.6 system-ui,sans-serif}main{max-width:540px;margin:24px;padding:40px;border:1px solid #304459;border-radius:20px;background:#182536}.brand{color:#6fe0c4;letter-spacing:.12em;font-size:13px;font-weight:700}h1{font-size:32px;line-height:1.15;margin:24px 0 16px}p{color:#bdcbdc}code{display:block;padding:12px;background:#101724;border-radius:8px;overflow-wrap:anywhere}a{display:inline-block;padding:12px 18px;margin-top:18px;border-radius:8px;background:#6fe0c4;color:#0c2522;text-decoration:none;font-weight:700}</style></head><body><main><div class="brand">CYBERSHIELD AI</div><h1>Cette requête a été bloquée.</h1><p>Notre protection a détecté une entrée qui nécessite une vérification. Vous pouvez revenir à l’accueil et réessayer avec une saisie différente.</p><p>Si le problème persiste, transmettez cette référence à l’administrateur :</p><code>' . $id . '</code><a href="../index.php">Revenir à l’accueil</a></main></body></html>';
        exit;
    }
}
