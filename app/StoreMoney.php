<?php
declare(strict_types=1);

/** Prix publics en francs CFA ; les instantanés historiques restent inchangés. */
final class StoreMoney
{
    public const MAX_EURO_CENTS = 100000000;

    /** Parité fixe 655,957 XOF/EUR ; arrondi d'un prix unitaire au multiple de 5. */
    public static function fromEuroCents(int $cents): int
    {
        if ($cents < 0 || $cents > self::MAX_EURO_CENTS) {
            throw new InvalidArgumentException('Le montant du catalogue est hors limites.');
        }
        if ($cents === 0) { return 0; }
        // Entiers uniquement : les unités arrondies servent ensuite aux lignes
        // et au total. Ne jamais reconvertir le total EUR après multiplication.
        return max(5, intdiv($cents * 655957 + 250000, 500000) * 5);
    }

    public static function formatXof(int $amount): string
    {
        if ($amount < 0) { throw new InvalidArgumentException('Montant en francs CFA invalide.'); }
        return preg_replace('/\B(?=(\d{3})+(?!\d))/', ' ', (string) $amount) . ' FCFA';
    }

    /** Panier validé : chaque article contient price (catalogue EUR) et qty. */
    public static function cartTotal(array $items): int
    {
        if (count($items) > 100) { throw new InvalidArgumentException('Panier trop volumineux.'); }
        $total = 0;
        $legacyTotal = 0;
        foreach ($items as $item) {
            if (!is_array($item)) { throw new InvalidArgumentException('Article du panier invalide.'); }
            $unit = self::catalogueCents($item['price'] ?? null);
            $quantity = self::quantity($item['qty'] ?? null);
            $legacyTotal += $unit * $quantity;
            if ($legacyTotal > self::MAX_EURO_CENTS) {
                throw new InvalidArgumentException('Le montant du panier est hors limites.');
            }
            $total += self::fromEuroCents($unit) * $quantity;
        }
        return $total;
    }

    /** Ligne d'instantané : unit_price_cents et quantity, sans prix navigateur. */
    public static function orderLine(array $line): int
    {
        $unit = filter_var($line['unit_price_cents'] ?? null, FILTER_VALIDATE_INT);
        $quantity = self::quantity($line['quantity'] ?? null);
        if ($unit === false || $unit < 0 || $unit > intdiv(self::MAX_EURO_CENTS, $quantity)) {
            throw new InvalidArgumentException('Prix de ligne de commande invalide.');
        }
        return self::fromEuroCents($unit) * $quantity;
    }

    private static function quantity(mixed $value): int
    {
        $quantity = filter_var($value, FILTER_VALIDATE_INT);
        if ($quantity === false || $quantity < 1 || $quantity > 99) {
            throw new InvalidArgumentException('La quantité doit être comprise entre 1 et 99.');
        }
        return $quantity;
    }

    private static function catalogueCents(mixed $price): int
    {
        if (is_float($price)) {
            if (!is_finite($price) || $price < 0 || $price > self::MAX_EURO_CENTS / 100) {
                throw new InvalidArgumentException('Prix du catalogue invalide.');
            }
            // refresh_cart conserve actuellement le DECIMAL du catalogue en
            // float. Sa représentation à deux décimales restaure ce DECIMAL.
            $price = number_format($price, 2, '.', '');
        } elseif (is_int($price)) {
            $price = (string) $price;
        }
        if (!is_string($price) || !preg_match('/^(\d{1,8})(?:\.(\d{1,2}))?$/D', $price, $match)) {
            throw new InvalidArgumentException('Prix du catalogue invalide.');
        }
        $cents = (int) $match[1] * 100 + (int) str_pad($match[2] ?? '', 2, '0');
        if ($cents > self::MAX_EURO_CENTS) { throw new InvalidArgumentException('Prix du catalogue hors limites.'); }
        return $cents;
    }
}
