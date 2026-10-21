<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require_once dirname(__DIR__) . '/app/StoreMoney.php';
require_once dirname(__DIR__) . '/app/cart_helpers.php';

$checks = 0;
function money_check(bool $condition, string $description): void
{
    global $checks;
    if (!$condition) { throw new RuntimeException('ÉCHEC : ' . $description); }
    $checks++;
    echo 'OK ' . $description . PHP_EOL;
}
function money_rejects(callable $action, string $description): void
{
    try { $action(); } catch (InvalidArgumentException $exception) {
        money_check(true, $description); return;
    }
    throw new RuntimeException('ÉCHEC : ' . $description);
}

try {
    money_check(StoreMoney::fromEuroCents(0) === 0, 'Un montant nul reste nul pour les vues de panier vide');
    money_check(StoreMoney::fromEuroCents(1) === 5 && StoreMoney::fromEuroCents(2) === 15, 'Petits prix positifs arrondis au multiple de cinq le plus proche');
    money_check(StoreMoney::fromEuroCents(14900) === 97740, 'Parité entière : 149 euros internes donnent 97 740 FCFA');
    money_check(StoreMoney::fromEuroCents(750) === 4920, 'Une unité à 7,50 donne 4 920 FCFA');
    money_check(StoreMoney::fromEuroCents(StoreMoney::MAX_EURO_CENTS) === 655957000, 'Borne haute convertie sans dépassement entier');
    money_rejects(static fn() => StoreMoney::fromEuroCents(-1), 'Montant négatif refusé');
    money_rejects(static fn() => StoreMoney::fromEuroCents(StoreMoney::MAX_EURO_CENTS + 1), 'Montant excessif refusé avant multiplication');
    money_check(StoreMoney::formatXof(97740) === '97 740 FCFA', 'Prix public sans euros ni décimales');
    money_check(StoreMoney::formatXof(0) === '0 FCFA', 'Total vide formaté en FCFA');
    money_check(StoreMoney::formatXof(PHP_INT_MAX) === '9 223 372 036 854 775 807 FCFA', 'Formatage des grands entiers sans conversion flottante');
    money_rejects(static fn() => StoreMoney::formatXof(-5), 'Formatage d’un montant négatif refusé');

    $cart = [['id' => 1, 'name' => 'Produit', 'price' => '149.00', 'qty' => 2]];
    money_check(StoreMoney::cartTotal([]) === 0, 'Panier vide sans prix fictif');
    money_check(StoreMoney::cartTotal($cart) === 195480, 'Deux unités affichées à 97 740 donnent exactement 195 480 FCFA');
    money_check(StoreMoney::cartTotal($cart) !== StoreMoney::fromEuroCents(29800), 'Le total ne reconvertit pas la somme EUR avec un autre arrondi');
    money_check(cart_total_xof($cart) === StoreMoney::cartTotal($cart), 'Helper de panier partagé avec le même calcul');
    money_check(StoreMoney::cartTotal([['price' => 149.0, 'qty' => '2'], ['price' => '7.50', 'qty' => 3]]) === 210240, 'Prix DECIMAL et float de session, quantités et plusieurs lignes cohérents');
    money_check(StoreMoney::cartTotal([['price' => 0.1, 'qty' => 3]]) === 195, 'Prix décimal court sans dérive binaire');
    money_check(StoreMoney::orderLine(['unit_price_cents' => '14900', 'quantity' => '2']) === StoreMoney::cartTotal($cart), 'Ligne de commande et panier produisent le même total');
    money_check(StoreMoney::orderLine(['unit_price_cents' => 0, 'quantity' => 1]) === 0, 'Ligne gratuite reste gratuite');
    money_rejects(static fn() => StoreMoney::cartTotal([['price' => '149.00', 'qty' => 0]]), 'Quantité nulle refusée');
    money_rejects(static fn() => StoreMoney::cartTotal([['price' => '149.00', 'qty' => 100]]), 'Quantité au-dessus de 99 refusée');
    money_rejects(static fn() => StoreMoney::cartTotal([['price' => '1e2', 'qty' => 1]]), 'Notation de prix ambiguë refusée');
    money_rejects(static fn() => StoreMoney::cartTotal([['price' => INF, 'qty' => 1]]), 'Prix non fini refusé');
    money_rejects(static fn() => StoreMoney::cartTotal([['price' => '1000000.00', 'qty' => 2]]), 'Total borné avant conversion de plusieurs unités');
    money_rejects(static fn() => StoreMoney::cartTotal(array_fill(0, 101, ['price' => '1.00', 'qty' => 1])), 'Panier de plus de 100 lignes refusé');
    money_rejects(static fn() => StoreMoney::orderLine(['unit_price_cents' => -1, 'quantity' => 1]), 'Prix de ligne négatif refusé');
    money_rejects(static fn() => StoreMoney::orderLine(['unit_price_cents' => 14900, 'quantity' => 1.5]), 'Quantité fractionnaire refusée');
    money_rejects(static fn() => StoreMoney::orderLine(['unit_price_cents' => '14900 OR 1=1', 'quantity' => 1]), 'Prix de ligne non entier refusé');
    echo $checks . " contrôles monétaires réussis ; aucune base ni transaction financière utilisée.\n";
} catch (Throwable $exception) {
    fwrite(STDERR, $exception->getMessage() . PHP_EOL);
    exit(1);
}
