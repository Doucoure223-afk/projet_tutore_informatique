<?php
declare(strict_types=1);

/** Prefer a mounted secret file in containers; keep environment support for Wamp installs. */
function cybershield_database_password(): string
{
    $secretPath = getenv('DB_PASSWORD_FILE');
    if (!is_string($secretPath) || $secretPath === '') { return getenv('DB_PASSWORD') ?: ''; }
    $password = @file_get_contents($secretPath);
    if ($password === false || trim($password) === '') {
        throw new RuntimeException('Secret de base de données absent.');
    }
    if (strlen($password) > 4096) { throw new RuntimeException('Secret de base de données invalide.'); }
    return rtrim($password, "\r\n");
}
