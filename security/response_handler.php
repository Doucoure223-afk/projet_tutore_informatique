<?php
class ResponseHandler {
    public static function blockRequest($attackType, $payload) {
        http_response_code(403);
        
        // En-têtes de sécurité
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('X-XSS-Protection: 1; mode=block');
        
        // Page de blocage
        self::showBlockedPage($attackType, $payload);
        exit();
    }
    
    private static function showBlockedPage($attackType, $payload) {
        ?>
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Requête Bloquée - Sécurité</title>
            <style>
                           body {
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    color: white;
                }
                .blocked-container {
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                    text-align: center;
                    max-width: 500px;
                }
                h1 {
                    color: #ff6b6b;
                    font-size: 2.5em;
                    margin-bottom: 20px;
                }
                .warning-icon {
                    font-size: 4em;
                    margin-bottom: 20px;
                    transition:  2ms;
                }
                .details {
                    background: rgba(0,0,0,0.2);
                    padding: 15px;
                    border-radius: 8px;
                    margin: 20px 0;
                    text-align: left;
                    font-family: monospace;
                    font-size: 0.9em;
                }
                .back-button {
                    background: #4CAF50;
                    color: white;
                    border: none;
                    padding: 12px 30px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 1em;
                    margin-top: 20px;
                    text-decoration: none;
                    display: inline-block;
                }
                .alert-id {
                    background: rgba(255,255,255,0.1);
                    padding: 5px 10px;
                    border-radius: 3px;
                    font-family: monospace;
                    margin-top: 20px;
                    font-size: 0.9em;
                }
            </style>
        </head>
        <body></body>
            <div class="blocked-container">
                <div class="warning-icon">Alert</div>
                <h1>Requête Bloquée</h1>
                <p>Une tentative d'attaque a été détectée et bloquée par notre système de sécurité.</p>
                
                <div class="details">
                    <strong>Type d'attaque :</strong> <?php echo htmlspecialchars($attackType); ?><br>
                    <strong>Payload détecté :</strong> <?php echo htmlspecialchars(substr($payload, 0, 100)); ?><br>
                    <strong>Adresse IP :</strong> <?php echo $_SERVER['REMOTE_ADDR'] ?? 'Inconnue'; ?><br>
                    <strong>Heure :</strong> <?php echo date('Y-m-d H:i:s'); ?>
                </div>
                
                <p>Si vous pensez qu'il s'agit d'une erreur, contactez l'administrateur.</p>
                
                <a href="javascript:history.back()" class="back-button">← Retour à la page précédente</a>
                
                <div class="alert-id">
                    ID d'alerte : <?php echo uniqid('SEC_'); ?>
                </div>
            </div>
        </body>
        </html>
        <?php
    }
}
?>