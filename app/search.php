<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/store_layout.php';

$user = current_user();
$search_query = trim(input_text($_GET, 'q'));
$selectedCategory = trim(input_text($_GET, 'category'));
$term = '%' . $search_query . '%';
$params = [$term, $term, $term];
$sql = 'SELECT id, name, description, category, price, stock FROM products WHERE (name LIKE ? OR description LIKE ? OR category LIKE ?)';
if ($selectedCategory !== '') { $sql .= ' AND category = ?'; $params[] = $selectedCategory; }
$sql .= ' ORDER BY id LIMIT 100';
$result = execute_query_secure($sql, $params);
$results = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
$categoriesResult = execute_query_secure("SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category <> '' ORDER BY category");
$categories = $categoriesResult ? $categoriesResult->fetch_all(MYSQLI_ASSOC) : [];
$cart_notice = $_SESSION['cart_notice'] ?? '';
unset($_SESSION['cart_notice']);
$cartIds = [];
foreach ($_SESSION['cart'] ?? [] as $item) { $cartIds[(int) ($item['id'] ?? 0)] = (int) ($item['qty'] ?? 0); }
function catalogue_filter_url(string $category, string $query): string {
    $params = [];
    if ($query !== '') { $params['q'] = $query; }
    if ($category !== '') { $params['category'] = $category; }
    return 'search.php' . ($params ? '?' . http_build_query($params) : '') . '#products';
}
?>
<!doctype html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#f5f4f0">
    <title>Le catalogue · CyberShield AI</title>
    <link rel="stylesheet" href="store.css?v=<?= (int) filemtime(__DIR__ . '/store.css') ?>">
    <link rel="stylesheet" href="catalogue.css?v=<?= (int) filemtime(__DIR__ . '/catalogue.css') ?>">
</head>
<body class="store-page catalogue-page">
<?php store_header('catalogue', $user); ?>
<main id="main-content" class="store-main">
    <section class="catalogue-hero" aria-labelledby="catalogue-title">
        <div class="catalogue-hero-copy">
            <p class="store-eyebrow">LA BOUTIQUE CYBERSHIELD</p>
            <h1 id="catalogue-title">Le bon équipement.<br><em>Tout simplement.</em></h1>
            <p class="catalogue-intro">Des appareils et des accessoires pour votre quotidien. Choisissez, ajoutez au panier et retrouvez vos commandes dans votre espace.</p>
        </div>
        <div class="catalogue-signature" aria-hidden="true">
            <div class="catalogue-signature-symbol"><?= store_icon('package') ?></div>
            <span>Le quotidien,<br>bien équipé.</span>
            <small>CYBERSHIELD / COLLECTION</small>
        </div>
    </section>
    <?php if ($cart_notice): ?>
        <div class="catalogue-feedback" role="status"><span class="catalogue-feedback-icon"><?= store_icon('check') ?></span><span><?= escape_output($cart_notice) ?></span><a href="panier.php">Voir mon panier <?= store_icon('arrow') ?></a></div>
    <?php endif; ?>
    <section class="catalogue-selection" id="products" aria-labelledby="products-title">
        <div class="catalogue-toolbar">
            <div class="catalogue-section-heading"><p class="store-eyebrow">À DÉCOUVRIR</p><h2 id="products-title"><?= $search_query !== '' ? 'Votre recherche' : 'Le catalogue' ?> <span><?= count($results) ?></span></h2></div>
            <form method="get" action="search.php#products" class="catalogue-search" role="search">
                <label for="product-search" class="sr-only">Rechercher un produit</label><?= store_icon('search') ?>
                <input type="search" id="product-search" name="q" placeholder="Rechercher un produit…" value="<?= escape_output($search_query) ?>">
                <?php if ($selectedCategory !== ''): ?><input type="hidden" name="category" value="<?= escape_output($selectedCategory) ?>"><?php endif; ?>
                <button type="submit" aria-label="Lancer la recherche"><?= store_icon('arrow') ?></button>
            </form>
        </div>
        <div class="catalogue-filterbar">
            <nav class="catalogue-filters" aria-label="Catégories du catalogue">
                <a href="<?= escape_output(catalogue_filter_url('', $search_query)) ?>" <?= $selectedCategory === '' ? 'aria-current="true"' : '' ?>>Tout voir</a>
                <?php foreach ($categories as $category): $categoryName = (string) $category['category']; ?>
                    <a href="<?= escape_output(catalogue_filter_url($categoryName, $search_query)) ?>" <?= $selectedCategory === $categoryName ? 'aria-current="true"' : '' ?>><?= escape_output($categoryName) ?></a>
                <?php endforeach; ?>
            </nav>
            <span class="catalogue-result-count"><?= count($results) ?> <?= count($results) === 1 ? 'produit' : 'produits' ?></span>
        </div>
        <?php if ($search_query !== ''): ?><p class="catalogue-query">Résultats pour <strong>« <?= escape_output($search_query) ?> »</strong><a href="<?= escape_output(catalogue_filter_url($selectedCategory, '')) ?>"><?= store_icon('close') ?> Effacer la recherche</a></p><?php endif; ?>
        <?php if ($results): ?>
            <div class="catalogue-grid">
                <?php foreach ($results as $product): $available = (int) $product['stock'] > 0; $inCart = $cartIds[(int) $product['id']] ?? 0; ?>
                    <article class="catalogue-product">
                        <div class="catalogue-product-art"><span class="catalogue-product-category"><?= escape_output($product['category'] ?: 'Équipement') ?></span><?= store_product_art($product) ?><?php if (!$available): ?><span class="catalogue-stock-badge">Indisponible</span><?php endif; ?></div>
                        <div class="catalogue-product-body">
                            <div class="catalogue-product-title"><h3><?= escape_output($product['name']) ?></h3><span><?= store_money((float) $product['price']) ?></span></div>
                            <p><?= escape_output($product['description']) ?></p>
                            <div class="catalogue-product-bottom"><span class="catalogue-availability <?= !$available ? 'is-unavailable' : '' ?>"><i aria-hidden="true"></i><?= $available ? 'En stock' : 'Rupture de stock' ?></span><?php if ($inCart > 0): ?><a class="catalogue-in-cart" href="panier.php"><?= store_icon('bag') ?><?= $inCart ?> au panier</a><?php endif; ?></div>
                            <?php if ($available): ?>
                                <form method="post" action="panier.php" class="catalogue-add-form">
                                    <input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>"><input type="hidden" name="action" value="add"><input type="hidden" name="product_id" value="<?= (int) $product['id'] ?>"><input type="hidden" name="q" value="<?= escape_output($search_query) ?>"><input type="hidden" name="category" value="<?= escape_output($selectedCategory) ?>">
                                    <button type="submit" class="catalogue-add-button" aria-label="Ajouter <?= escape_output($product['name']) ?> au panier">Ajouter au panier <?= store_icon('plus') ?></button>
                                </form>
                            <?php else: ?><button type="button" class="catalogue-add-button" disabled>Actuellement indisponible <?= store_icon('close') ?></button><?php endif; ?>
                        </div>
                    </article>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <div class="catalogue-empty" role="status"><span class="catalogue-empty-icon"><?= store_icon('search') ?></span><h3>Aucun produit ne correspond.</h3><p>Essayez un mot plus court ou consultez l’ensemble du catalogue.</p><a class="store-button store-button--primary" href="search.php#products">Voir tous les produits <?= store_icon('arrow') ?></a></div>
        <?php endif; ?>
    </section>
    <aside class="catalogue-bottom-note"><?= store_icon('bag') ?><p><strong>Votre sélection vous attend.</strong><span>Le panier réunit vos articles avant la validation de votre commande.</span></p><a href="panier.php">Ouvrir le panier <?= store_icon('arrow') ?></a></aside>
</main>
<?php store_footer(); ?>
</body>
</html>


