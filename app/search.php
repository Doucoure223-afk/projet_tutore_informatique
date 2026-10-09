<?php
require_once __DIR__ . '/config.php';
$results = [];
$search_query = trim(input_text($_GET, 'q'));
$term = '%' . $search_query . '%';
$result = execute_query_secure('SELECT id, name, description, category, price, stock FROM products WHERE name LIKE ? OR description LIKE ? OR category LIKE ? ORDER BY id LIMIT 100', [$term, $term, $term]);
if ($result) { $results = $result->fetch_all(MYSQLI_ASSOC); }
$cart_notice = $_SESSION['cart_notice'] ?? '';
unset($_SESSION['cart_notice']);
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Catalogue de démonstration · CyberShield AI</title>
    <link rel="stylesheet" href="theme.css?v=<?= (int) filemtime(__DIR__ . '/theme.css') ?>">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Catalogue de démonstration</h1>
            <p class="subtitle">Rechercher parmi le catalogue</p>
            <form method="GET" action="" class="search-form">
                <div class="search-box">
                    <label class="sr-only" for="product-search">Nom, description ou catégorie du produit</label>
                    <input type="search" id="product-search" name="q" class="search-input" placeholder="Ex. clavier, ordinateur" value="<?php echo htmlspecialchars($search_query); ?>">
                    <button type="submit" class="search-btn">Rechercher</button>
                    <?php if (!empty($search_query)): ?><a href="search.php" class="clear-link">Effacer la recherche</a><?php endif; ?>
                </div>
            </form>
            <nav class="nav-links">
                <a href="search.php" aria-current="page">Recherche</a>
                <a href="login.php">Connexion</a>
                <a href="dashboard.php">Mon espace</a>
                <a href="panier.php">Panier<?php $cart_count = !empty($_SESSION['cart']) ? array_sum(array_column($_SESSION['cart'], 'qty')) : 0; if ($cart_count > 0) echo ' (' . $cart_count . ')'; ?></a>
                <a href="inscription.php">Inscription</a>
            </nav>
        </div>
        <?php if ($cart_notice): ?><p class="results-card" role="status"><?= escape_output($cart_notice) ?></p><?php endif; ?>
        <div class="results-card">
            <div class="results-header">
                <h2><?= $search_query === '' ? 'Catalogue de démonstration' : 'Résultats pour « ' . escape_output($search_query) . ' »' ?></h2>
                <span class="results-count"><?php echo count($results); ?> produit(s)</span>
            </div>
            <?php if (!empty($results)): ?>
                <div class="results-container">
                    <?php foreach ($results as $product): ?>
                        <div class="product-card">
                            <div class="product-icon"><svg width="28" height="28" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><rect width="24" height="24" fill="#dce7dd"/><g fill="#285c4d"><rect x="3" y="4" width="4" height="4" rx="1"/><rect x="10" y="4" width="4" height="4" rx="1"/><rect x="17" y="4" width="4" height="4" rx="1"/><rect x="3" y="10" width="4" height="4" rx="1"/><rect x="10" y="10" width="4" height="4" rx="1"/><rect x="17" y="10" width="4" height="4" rx="1"/></g></svg></div>
                            <div class="product-info">
                                <div class="product-name"><?php echo htmlspecialchars($product['name']); ?></div>
                                <div class="product-description"><?php echo htmlspecialchars($product['description']); ?></div>
                                <div class="product-meta">
                                    <span class="product-price"><?php echo htmlspecialchars($product['price'] ?? '0'); ?> €</span>
                                    <span class="product-stock"><?php echo htmlspecialchars($product['stock'] ?? 0); ?> en stock</span>
                                </div>
                                <?php if ((int) $product['stock'] > 0): ?>
                                <form method="post" action="panier.php">
                                    <input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>">
                                    <input type="hidden" name="action" value="add">
                                    <input type="hidden" name="product_id" value="<?= (int) $product['id'] ?>">
                                    <input type="hidden" name="q" value="<?= escape_output($search_query) ?>">
                                    <button type="submit" class="btn-add-cart">Ajouter au panier</button>
                                </form>
                                <?php else: ?><span class="product-stock">Indisponible</span><?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="no-results"><h3>Aucun résultat trouvé</h3><p>Essayez un autre terme ou ouvrez « Parcourir par catégorie » plus bas.</p></div>
            <?php endif; ?>
        </div>
        <section class="ecom-section">
            <details class="categories-disclosure">
                <summary>Parcourir par catégorie</summary>
                <div class="categories-grid">
                    <a href="search.php?q=ordinateur" class="category-card"><span class="category-symbol" aria-hidden="true">O</span><span>Ordinateurs</span></a>
                    <a href="search.php?q=clavier" class="category-card"><span class="category-symbol" aria-hidden="true">C</span><span>Claviers</span></a>
                    <a href="search.php?q=souris" class="category-card"><span class="category-symbol" aria-hidden="true">S</span><span>Souris &amp; périphériques</span></a>
                    <a href="search.php?q=casque" class="category-card"><span class="category-symbol" aria-hidden="true">A</span><span>Audio &amp; casques</span></a>
                </div>
            </details>
            <p class="catalog-disclosure-note">Catalogue de démonstration : panier et paiement simulés, aucun achat réel.</p>
        </section>
    </div>
</body>
</html>
