<?php
declare(strict_types=1);
require_once __DIR__ . '/StoreMoney.php';

/** Shared storefront structure. Call after the page has completed its redirects. */
function store_icon(string $name): string {
    $paths = [
        'search' => '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
        'bag' => '<path d="M5 7h14l1 14H4L5 7Z"/><path d="M9 8V6a3 3 0 0 1 6 0v2"/>',
        'arrow' => '<path d="M4 12h16m-6-6 6 6-6 6"/>',
        'chevron' => '<path d="m9 5 7 7-7 7"/>',
        'check' => '<path d="m5 12 4 4L19 6"/>',
        'shield' => '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
        'grid' => '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
        'user' => '<circle cx="12" cy="8" r="4"/><path d="M4 21v-2a8 8 0 0 1 16 0v2"/>',
        'logout' => '<path d="M9 4H4v16h5m5-13 5 5-5 5m-5-5h11"/>',
        'clock' => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        'package' => '<path d="m12 3 9 5v9l-9 5-9-5V8l9-5Zm0 9 9-4m-9 4L3 8m9 4v10M7 5.8 16 11"/>',
        'minus' => '<path d="M5 12h14"/>',
        'plus' => '<path d="M5 12h14M12 5v14"/>',
        'close' => '<path d="m6 6 12 12M6 18 18 6"/>',
        'lock' => '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 4v3"/>',
    ];
    return '<svg class="store-icon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">' . ($paths[$name] ?? $paths['package']) . '</svg>';
}

function store_money(float $amount): string { return StoreMoney::formatXof(StoreMoney::fromEuroCents((int) round($amount * 100))); }
function store_xof(int $amount): string { return StoreMoney::formatXof($amount); }

/** Product illustrations are local, decorative SVGs, never external tracking images. */
function store_product_art(array $product): string {
    $name = mb_strtolower((string) ($product['name'] ?? ''));
    $common = 'stroke="#294c40" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"';
    if (str_contains($name, 'couteur') || str_contains($name, 'casque')) {
        $drawing = '<path d="M75 112V91a45 45 0 0 1 90 0v21" fill="none" stroke-width="13"/><path d="M74 105v39m92-39v39" stroke-width="19"/><rect x="66" y="101" width="23" height="53" rx="10" fill="#b4c8b5"/><rect x="151" y="101" width="23" height="53" rx="10" fill="#b4c8b5"/><path d="M89 59a41 41 0 0 1 62 0" fill="none" stroke="#dce4d8" stroke-width="6"/>';
    } elseif (str_contains($name, 'laptop') || str_contains($name, 'ordinateur')) {
        $drawing = '<rect x="51" y="48" width="138" height="91" rx="6" fill="#526b60"/><rect x="58" y="55" width="124" height="76" rx="2" fill="#cedbc8"/><path d="m80 122 29-43 22 25 15-17 30 35" fill="#9fb59d" stroke="none"/><path d="m51 139-19 16c-2 3 0 6 6 6h164c6 0 8-3 6-6l-19-16H51Z" fill="#b6c7b3"/><path d="M107 147h26" stroke="#617c6a"/>';
    } elseif (str_contains($name, 'montre')) {
        $drawing = '<rect x="100" y="20" width="40" height="160" rx="13" fill="#bbcbb8"/><rect x="86" y="58" width="68" height="87" rx="18" fill="#3d5b4d"/><rect x="92" y="65" width="56" height="73" rx="13" fill="#dae3d1"/><circle cx="120" cy="102" r="22" fill="none" stroke="#7b9981"/><path d="M120 85v18l12 7"/><path d="M158 87v14" stroke-width="5"/>';
    } elseif (str_contains($name, 'clavier')) {
        $keys = '';
        for ($row = 0; $row < 3; $row++) for ($column = 0; $column < 10; $column++) {
            $keys .= '<rect x="' . (46 + $column * 15) . '" y="' . (77 + $row * 16) . '" width="10" height="10" rx="1.5" fill="#e4eadd" stroke="none"/>';
        }
        $drawing = '<rect x="36" y="65" width="169" height="78" rx="7" fill="#69826f"/>' . $keys . '<rect x="83" y="126" width="73" height="9" rx="2" fill="#d8e1cf" stroke="none"/>';
    } elseif (str_contains($name, 'souris')) {
        $drawing = '<path d="M120 38c-31 0-47 28-47 64v16c0 32 19 50 47 50s47-18 47-50v-16c0-36-16-64-47-64Z" fill="#a8bea6"/><path d="M120 39v50M74 100h92" fill="none"/><rect x="115" y="57" width="10" height="25" rx="5" fill="#4e6e59" stroke="none"/>';
    } elseif (str_contains($name, 'webcam')) {
        $drawing = '<path d="M104 119v28m32-28v28m-48 8h64"/><rect x="49" y="58" width="142" height="69" rx="22" fill="#a9bea7"/><circle cx="120" cy="92" r="25" fill="#365448"/><circle cx="120" cy="92" r="15" fill="#cad9c4"/><circle cx="166" cy="89" r="3" fill="#345245" stroke="none"/>';
    } elseif (str_contains($name, 'chargeur')) {
        $drawing = '<path d="M169 104h24c14 0 13-26 2-26h-6" fill="none"/><ellipse cx="113" cy="116" rx="66" ry="30" fill="#a9bea7"/><ellipse cx="113" cy="107" rx="66" ry="30" fill="#d9e2cf"/><path d="m116 89-14 20h14l-6 16 20-24h-14l7-12" fill="#68896d" stroke="none"/>';
    } else {
        $drawing = '<rect x="82" y="26" width="77" height="151" rx="13" fill="#496855"/><rect x="88" y="34" width="65" height="134" rx="8" fill="#c8d8bf"/><path d="m91 151 40-72 22 39v46H91Z" fill="#9db696" stroke="none"/><rect x="107" y="36" width="27" height="5" rx="2.5" fill="#496855" stroke="none"/>';
    }
    return '<svg class="store-product-art" aria-hidden="true" viewBox="0 0 240 200"><ellipse cx="120" cy="182" rx="68" ry="5" fill="#dee3d6"/><g ' . $common . '>' . $drawing . '</g></svg>';
}

function store_header(string $active, ?array $user = null): void {
    $count = array_sum(array_map(static fn($item) => is_array($item) ? max(0, (int) ($item['qty'] ?? 0)) : 0, $_SESSION['cart'] ?? []));
    ?>
    <a class="store-skip" href="#main-content">Aller au contenu</a>
    <header class="store-header"><div class="store-header-inner">
      <a class="store-brand" href="search.php"><span class="store-brand-mark" aria-hidden="true">C<span>·</span></span><span>CyberShield <b>AI</b><small>LA BOUTIQUE</small></span></a>
      <nav class="store-nav" aria-label="Navigation de la boutique">
        <a href="search.php" <?= $active === 'catalogue' ? 'aria-current="page"' : '' ?>>Catalogue</a>
        <a href="panier.php" <?= $active === 'cart' || $active === 'checkout' ? 'aria-current="page"' : '' ?>>Panier<span class="store-count" aria-label="<?= $count ?> article<?= $count > 1 ? 's' : '' ?>"><?= $count ?></span></a>
        <?php if ($user): ?><a href="dashboard.php#orders" <?= $active === 'account' ? 'aria-current="page"' : '' ?>>Mes commandes</a><?php endif; ?>
      </nav>
      <div class="store-header-actions">
        <?php if ($user): ?><a class="store-user" href="dashboard.php" aria-label="Mon compte"><?= store_icon('user') ?><span><?= escape_output($user['username']) ?></span></a><form class="store-logout" method="post" action="logout.php"><input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>"><button type="submit" aria-label="Se déconnecter"><?= store_icon('logout') ?></button></form>
        <?php else: ?><a class="store-signin" href="login.php" aria-label="Se connecter"><?= store_icon('user') ?><span>Se connecter</span></a><?php endif; ?>
      </div>
    </div></header>
    <?php
}

function store_steps(string $active): void {
    $steps = ['cart' => ['01', 'Panier'], 'checkout' => ['02', 'Commande'], 'payment' => ['03', 'Paiement']];
    ?><ol class="store-steps" aria-label="Étapes de la commande"><?php foreach ($steps as $key => [$number, $label]): ?><li <?= $active === $key ? 'aria-current="step"' : '' ?>><span><?= $number ?></span><?= $label ?></li><?php endforeach; ?></ol><?php
}

function store_footer(): void {
    ?><footer class="store-footer"><a href="../index.php">CyberShield AI <?= store_icon('arrow') ?></a><span>Catalogue · Commandes · Mon compte</span><a href="search.php">Retour au catalogue</a></footer><?php
}
