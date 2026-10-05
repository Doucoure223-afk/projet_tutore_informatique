<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (empty($_SESSION['authenticated']) || empty($_SESSION['user_id'])) {
    http_response_code(401);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode(['error' => 'Non autorisé']);
    exit;
}

require_once __DIR__ . '/../vendor/autoload.php';

use App\Infrastructure\ApplicationConfig;
use App\Security\Dashboard\SecurityDashboard;

ApplicationConfig::initialize(__DIR__ . '/..');

$logger = ApplicationConfig::getLogger('security');
$pdo = ApplicationConfig::getDatabase();
$dashboard = new SecurityDashboard($logger, $pdo, true);

$action = isset($_GET['action']) ? trim((string) $_GET['action']) : '';
$userId = (int) ($_SESSION['user_id'] ?? 0);

// Liste des sessions (historique des conversations)
if ($action === 'chat_sessions' && $userId > 0) {
    $sessions = [];
    try {
        $stmt = $pdo->prepare(
            'SELECT id, title, created_at FROM chat_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'
        );
        $stmt->execute([$userId]);
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $sessions[] = [
                'id' => (int) ($row['id'] ?? 0),
                'title' => $row['title'] ?? 'Conversation',
                'created_at' => $row['created_at'] ?? '',
            ];
        }
    } catch (Throwable $e) {
    }
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    echo json_encode(['sessions' => $sessions], JSON_UNESCAPED_UNICODE);
    exit;
}

// Nouveau chat : crée une nouvelle session et la retourne
if ($action === 'chat_new' && $userId > 0) {
    $sessionId = null;
    try {
        $title = 'Conversation du ' . date('d/m/Y à H:i');
        $stmt = $pdo->prepare('INSERT INTO chat_sessions (user_id, title) VALUES (?, ?)');
        $stmt->execute([$userId, $title]);
        $sessionId = (int) $pdo->lastInsertId();
    } catch (Throwable $e) {
    }
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    echo json_encode(['ok' => true, 'session_id' => $sessionId], JSON_UNESCAPED_UNICODE);
    exit;
}

// Historique du chat : messages d'une session (ou session courante / legacy)
if ($action === 'chat_history') {
    $messages = [];
    $sessionId = isset($_GET['session_id']) ? (int) $_GET['session_id'] : null;
    try {
        if ($sessionId > 0) {
            $stmt = $pdo->prepare(
                'SELECT role, content, created_at FROM chat_messages WHERE user_id = ? AND session_id = ? ORDER BY created_at ASC LIMIT 100'
            );
            $stmt->execute([$userId, $sessionId]);
        } else {
            // Dernière session ou messages sans session (legacy)
            $stmt = $pdo->prepare(
                'SELECT id FROM chat_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1'
            );
            $stmt->execute([$userId]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row) {
                $sessionId = (int) $row['id'];
                $stmt = $pdo->prepare(
                    'SELECT role, content, created_at FROM chat_messages WHERE user_id = ? AND session_id = ? ORDER BY created_at ASC LIMIT 100'
                );
                $stmt->execute([$userId, $sessionId]);
            } else {
                $stmt = $pdo->prepare(
                    'SELECT role, content, created_at FROM chat_messages WHERE user_id = ? AND (session_id IS NULL OR session_id = 0) ORDER BY created_at ASC LIMIT 100'
                );
                $stmt->execute([$userId]);
            }
        }
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $messages[] = [
                'role' => $row['role'] ?? 'user',
                'content' => $row['content'] ?? '',
            ];
        }
    } catch (Throwable $e) {
    }
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    echo json_encode(['messages' => $messages, 'session_id' => $sessionId], JSON_UNESCAPED_UNICODE);
    exit;
}

// Assistant chat : logique déléguée à l'API Flask (POST /chat), persistance par session
if ($action === 'chat' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw = file_get_contents('php://input');
    $body = $raw !== false ? json_decode($raw, true) : null;
    $message = isset($body['message']) && is_string($body['message']) ? trim($body['message']) : '';
    $sessionId = isset($body['session_id']) ? (int) $body['session_id'] : null;
    try {
        if ($sessionId <= 0) {
            $stmt = $pdo->prepare('INSERT INTO chat_sessions (user_id, title) VALUES (?, ?)');
            $stmt->execute([$userId, 'Conversation du ' . date('d/m/Y à H:i')]);
            $sessionId = (int) $pdo->lastInsertId();
        }
    } catch (Throwable $e) {
        $sessionId = null;
    }
    $historyForFlask = [];
    try {
        if ($sessionId > 0) {
            $stmt = $pdo->prepare(
                'SELECT role, content FROM chat_messages WHERE user_id = ? AND session_id = ? ORDER BY created_at DESC LIMIT 10'
            );
            $stmt->execute([$userId, $sessionId]);
        } else {
            $stmt = $pdo->prepare(
                'SELECT role, content FROM chat_messages WHERE user_id = ? AND (session_id IS NULL OR session_id = 0) ORDER BY created_at DESC LIMIT 10'
            );
            $stmt->execute([$userId]);
        }
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $historyForFlask = array_reverse(array_map(fn($r) => ['role' => $r['role'] ?? 'user', 'content' => $r['content'] ?? ''], $rows));
    } catch (Throwable $e) {
    }
    $result = null;
    $flaskUrl = rtrim((string) ApplicationConfig::get('ai.flask_url', 'http://127.0.0.1:5000'), '/');
    $chatUrl = $flaskUrl . '/chat';
    $payload = json_encode(['message' => $message, 'history' => $historyForFlask], JSON_UNESCAPED_UNICODE);
    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\n",
            'content' => $payload,
            'timeout' => 90,
        ],
    ]);
    $json = @file_get_contents($chatUrl, false, $ctx);
    if ($json !== false) {
        $decoded = json_decode($json, true);
        if (is_array($decoded) && array_key_exists('reply', $decoded)) {
            $result = ['ok' => !empty($decoded['ok']), 'reply' => (string) $decoded['reply']];
        }
    }
    if ($result === null) {
        $result = $dashboard->chatAssistant($message);
    }
    $reply = (string) ($result['reply'] ?? '');
    try {
        $ins = $pdo->prepare('INSERT INTO chat_messages (user_id, session_id, role, content) VALUES (?, ?, ?, ?)');
        $ins->execute([$userId, $sessionId > 0 ? $sessionId : null, 'user', $message]);
        $ins->execute([$userId, $sessionId > 0 ? $sessionId : null, 'assistant', $reply]);
    } catch (Throwable $e) {
        try {
            $ins = $pdo->prepare('INSERT INTO chat_messages (user_id, role, content) VALUES (?, ?, ?)');
            $ins->execute([$userId, 'user', $message]);
            $ins->execute([$userId, 'assistant', $reply]);
        } catch (Throwable $e2) {
        }
    }
    if ($result !== null && $sessionId > 0) {
        $result['session_id'] = $sessionId;
    }
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    echo json_encode($result, JSON_UNESCAPED_UNICODE);
    exit;
}

$period = isset($_GET['period']) ? (int) $_GET['period'] : 7;
if (!in_array($period, [1, 7, 30], true)) {
    $period = 7;
}

$data = $dashboard->getRefreshData($period);

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-cache, no-store, must-revalidate');
echo json_encode($data, JSON_UNESCAPED_UNICODE);
exit;
