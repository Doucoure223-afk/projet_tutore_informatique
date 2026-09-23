<?php
/**
 * RECHERCHE VULNÉRABLE - DÉMONSTRATION SQL INJECTION
 * Aucune protection : concaténation directe dans les requêtes SQL.
 */
require_once 'config.php';

$results = [];
$search_query = isset($_GET['q']) ? trim($_GET['q']) : '';

if (!empty($search_query)) {
        $sql = "SELECT * FROM products WHERE 
                name LIKE '%$search_query%' OR 
                description LIKE '%$search_query%' OR 
                category LIKE '%$search_query%'";
        $result = execute_query_vulnerable($sql);
        if ($result) {
            while ($row = mysqli_fetch_assoc($result)) {
                $results[] = $row;
            }
        }
    }
    if (isset($_GET['test_union'])) {
        $test_sql = "SELECT * FROM products WHERE id = '" . $_GET['test_union'] . "'";
        $test_result = execute_query_vulnerable($test_sql);
    }
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recherche de produits</title>
    <link rel="stylesheet" href="style_search.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Recherche de produits</h1>
            <p class="subtitle">Rechercher parmi le catalogue</p>
            <form method="GET" action="" class="search-form">
                <div class="search-box">
                    <input type="text" name="q" class="search-input" placeholder="clavier" value="<?php echo htmlspecialchars($search_query); ?>">
                    <button type="submit" class="search-btn">Rechercher <i class="fas fa-search"></i></button>
                    <?php if (!empty($search_query)): ?><a href="search.php" class="clear-link">Effacer la recherche</a><?php endif; ?>
                </div>
            </form>
            <nav class="nav-links">
                <a href="search.php">Recherche</a>
                <a href="login.php">Connexion</a>
                <a href="dashboard.php">Dashboard</a>
                <a href="panier.php">Panier<?php $cart_count = !empty($_SESSION['cart']) ? array_sum(array_column($_SESSION['cart'], 'qty')) : 0; if ($cart_count > 0) echo ' (' . $cart_count . ')'; ?></a>
                <a href="inscription.php">Inscription</a>
            </nav>
        </div>
        <?php if (!empty($search_query)): ?>
        <div class="results-card">
            <div class="results-header">
                <h2>Résultats pour « <?php echo htmlspecialchars($search_query); ?> »</h2>
                <span class="results-count"><?php echo count($results); ?> produit(s)</span>
            </div>
            <?php if (!empty($results)): ?>
                <div class="results-container">
                    <?php foreach ($results as $product): ?>
                        <div class="product-card">
                            <div class="product-icon"><svg width="28" height="28" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><rect width="24" height="24" fill="#a78bfa"/><g fill="rgba(255,255,255,0.9)"><rect x="3" y="4" width="4" height="4" rx="1"/><rect x="10" y="4" width="4" height="4" rx="1"/><rect x="17" y="4" width="4" height="4" rx="1"/><rect x="3" y="10" width="4" height="4" rx="1"/><rect x="10" y="10" width="4" height="4" rx="1"/><rect x="17" y="10" width="4" height="4" rx="1"/></g></svg></div>
                            <div class="product-info">
                                <div class="product-name"><?php echo htmlspecialchars($product['name']); ?></div>
                                <div class="product-description"><?php echo htmlspecialchars($product['description']); ?></div>
                                <div class="product-meta">
                                    <span class="product-price"><?php echo htmlspecialchars($product['price'] ?? '0'); ?> €</span>
                                    <span class="product-stock"><?php echo htmlspecialchars($product['stock'] ?? 0); ?> en stock</span>
                                </div>
                                <a href="panier.php?add=<?php echo (int)($product['id'] ?? 0); ?>&from=search<?php echo !empty($search_query) ? '&q=' . urlencode($search_query) : ''; ?>" class="btn-add-cart"><i class="fas fa-cart-plus"></i> Ajouter au panier</a>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="no-results"><h3>Aucun résultat trouvé</h3><p>Essayez avec d'autres termes ou parcourez nos catégories ci-dessous</p></div>
            <?php endif; ?>
        </div>
        <?php endif; ?>
        <section class="ecom-section">
            <h3>Découvrez nos catégories</h3>
            <div class="categories-grid">
                <a href="search.php?q=ordinateur" class="category-card"><i class="fas fa-laptop"></i><span>Ordinateurs</span></a>
                <a href="search.php?q=clavier" class="category-card"><i class="fas fa-keyboard"></i><span>Claviers</span></a>
                <a href="search.php?q=souris" class="category-card"><i class="fas fa-mouse"></i><span>Souris &amp; Périphériques</span></a>
                <a href="search.php?q=casque" class="category-card"><i class="fas fa-headphones"></i><span>Audio &amp; Casques</span></a>
            </div>
            <div class="trust-badges">
                <div class="trust-item"><i class="fas fa-truck"></i> Livraison rapide</div>
                <div class="trust-item"><i class="fas fa-shield-alt"></i> Paiement sécurisé</div>
                <div class="trust-item"><i class="fas fa-undo"></i> Satisfait ou remboursé 14 jours</div>
                <div class="trust-item"><i class="fas fa-headset"></i> Support 7j/7</div>
            </div>
        </section>
    </div>
</body>
</html>
