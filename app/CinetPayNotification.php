<?php
declare(strict_types=1);
require_once __DIR__ . '/CinetPay.php';

/** Sépare l’authentification prestataire de la mutation transactionnelle du stock. */
final class CinetPayNotification
{
    public static function process(CinetPay $payments, array $posted, string $token, callable $reconcile): void
    {
        if (!$payments->isReady()) { throw new RuntimeException($payments->unavailableReason()); }
        $reference = $payments->verifyNotification($posted, $token);
        $verified = $payments->checkTransaction($reference);
        $reconcile($reference, $verified);
    }
}
