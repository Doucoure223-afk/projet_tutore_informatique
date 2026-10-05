<?php
declare(strict_types=1);

namespace App\Security\Response;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Factory de réponses de sécurité avec templates et i18n
 */
final class SecurityResponseFactory
{
    private const TEMPLATES = [
        'blocked' => __DIR__ . '/templates/blocked.html.php',
        'throttled' => __DIR__ . '/templates/throttled.html.php',
        'maintenance' => __DIR__ . '/templates/maintenance.html.php'
    ];
    
    public function __construct(
        private string $defaultLanguage = 'fr',
        private bool $debugMode = false
    ) {}
    
    /**
     * Crée une réponse de blocage pour injection SQL
     */
    public function createBlockedResponse(
        ServerRequestInterface $request,
        array $threatInfo
    ): ResponseInterface {
        $response = new \Slim\Psr7\Response();
        
        // En-têtes de sécurité modernes 2026
        $securityHeaders = [
            'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline';",
            'X-Frame-Options' => 'DENY',
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
            'Cross-Origin-Opener-Policy' => 'same-origin',
            'Cross-Origin-Embedder-Policy' => 'require-corp',
            'X-Permitted-Cross-Domain-Policies' => 'none'
        ];
        
        foreach ($securityHeaders as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        
        $html = $this->renderTemplate('blocked', [
            'threat' => $threatInfo,
            'request_id' => $request->getAttribute('request_id'),
            'timestamp' => date('c'),
            'debug' => $this->debugMode ? $threatInfo : null
        ]);
        
        $response->getBody()->write($html);
        
        return $response
            ->withStatus(403)
            ->withHeader('Content-Type', 'text/html; charset=utf-8');
    }
    
    private function renderTemplate(string $template, array $data): string
    {
        $templateFile = self::TEMPLATES[$template] ?? self::TEMPLATES['blocked'];
        
        if (!file_exists($templateFile)) {
            return $this->getDefaultTemplate($template, $data);
        }
        
        extract($data, EXTR_SKIP);
        ob_start();
        include $templateFile;
        return ob_get_clean();
    }
    
    private function getDefaultTemplate(string $template, array $data): string
    {
        return <<<HTML
        <!DOCTYPE html>
        <html lang="fr" data-theme="dark">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Sécurité - Requête Bloquée</title>
            <style>
                :root {
                    --primary: #2563eb;
                    --danger: #dc2626;
                    --warning: #f59e0b;
                    --success: #10b981;
                    --dark: #1e293b;
                    --light: #f8fafc;
                }
                
                * { margin: 0; padding: 0; box-sizing: border-box; }
                
                body {
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    color: var(--light);
                }
                
                .security-card {
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(20px);
                    border-radius: 24px;
                    padding: 48px;
                    max-width: 600px;
                    width: 100%;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                }
                
                .header {
                    text-align: center;
                    margin-bottom: 32px;
                }
                
                .icon {
                    font-size: 64px;
                    margin-bottom: 16px;
                    animation: pulse 2s infinite;
                }
                
                @keyframes pulse {
                    0%, 100% { transform: scale(1); }
                    50% { transform: scale(1.1); }
                }
                
                h1 {
                    font-size: 2.5rem;
                    font-weight: 800;
                    margin-bottom: 8px;
                    background: linear-gradient(to right, #ff6b6b, #ffa8a8);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                }
                
                .details {
                    background: rgba(0, 0, 0, 0.2);
                    border-radius: 12px;
                    padding: 24px;
                    margin: 24px 0;
                    font-family: 'Monaco', 'Consolas', monospace;
                    font-size: 0.9rem;
                }
                
                .detail-item {
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 12px;
                    padding-bottom: 12px;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                }
                
                .actions {
                    display: flex;
                    gap: 16px;
                    justify-content: center;
                    margin-top: 32px;
                }
                
                .btn {
                    padding: 14px 28px;
                    border-radius: 8px;
                    font-weight: 600;
                    text-decoration: none;
                    transition: all 0.3s;
                    border: none;
                    cursor: pointer;
                    font-size: 1rem;
                }
                
                .btn-primary {
                    background: var(--primary);
                    color: white;
                }
                
                .btn-secondary {
                    background: transparent;
                    color: white;
                    border: 2px solid rgba(255, 255, 255, 0.3);
                }
                
                .btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
                }
            </style>
        </head>
        <body>
            <div class="security-card">
                <div class="header">
                    <div class="icon">🚨</div>
                    <h1>Requête Sécurisée Bloquée</h1>
                    <p>Notre système de protection IA a détecté une menace potentielle</p>
                </div>
                
                <div class="details">
                    <div class="detail-item">
                        <span>ID Incident:</span>
                        <strong>{$data['request_id']}</strong>
                    </div>
                    <div class="detail-item">
                        <span>Type de menace:</span>
                        <span style="color: #ff6b6b;">{$data['threat']['type']}</span>
                    </div>
                    <div class="detail-item">
                        <span>Niveau de risque:</span>
                        <span style="color: #f59e0b;">{$data['threat']['risk_level']}</span>
                    </div>
                    <div class="detail-item">
                        <span>Heure:</span>
                        <span>{$data['timestamp']}</span>
                    </div>
                </div>
                
                <div style="text-align: center; margin: 24px 0;">
                    <p style="opacity: 0.8;">
                        Cet incident a été enregistré dans notre système de sécurité.<br>
                        En cas d'erreur, contactez notre équipe avec l'ID incident.
                    </p>
                </div>
                
                <div class="actions">
                    <a href="/" class="btn btn-primary">Retour à l'accueil</a>
                    <button onclick="history.back()" class="btn btn-secondary">Page précédente</button>
                </div>
                
                <div style="margin-top: 32px; text-align: center; font-size: 0.8rem; opacity: 0.6;">
                    <p>Système de sécurité • Version 2026.1 • Protection IA active</p>
                </div>
            </div>
            
            <script>
                // Analytics sécurisé
                const incidentData = {
                    id: '{$data['request_id']}',
                    type: 'security_block',
                    timestamp: '{$data['timestamp']}'
                };
                
                // Envoi sécurisé des données
                if (navigator.sendBeacon) {
                    navigator.sendBeacon('/api/security/incident', JSON.stringify(incidentData));
                }
            </script>
        </body>
        </html>
        HTML;
    }
}