# Commandes et paiement en ligne

Le panier prépare une véritable commande persistante et un suivi par compte. Le paiement en ligne choisi est un guichet hébergé **CinetPay**, adapté aux paiements Mobile Money et carte disponibles sur le compte marchand. Les moyens réellement proposés dépendent de l'activation de ce compte chez CinetPay.

## État exact de cette version

Le stockage des commandes, la validation des prix et du stock, les références non séquentielles et le traitement idempotent des confirmations sont implémentés. La migration ajoute `commerce_orders` et `commerce_order_items` ; elle ne remplace pas l'ancienne table `orders` et ne supprime aucune donnée.

**La communication externe CinetPay n'est pas implémentée ni activée dans cette version.** Une revue automatique d'autorisation a refusé l'ajout de l'envoi des coordonnées client et de commande vers le prestataire en l'absence d'accord explicite sur cette destination et ces données. `CinetPay::isReady()` reste donc faux, y compris si des variables sont renseignées. `startCheckout()` et `checkTransaction()` renvoient une indisponibilité. Aucun paiement ni statut de succès n'est fabriqué pour contourner cette limite.

Le bouton **« Enregistrer ma commande »** permet une véritable prise de commande locale après validation des coordonnées. Cette action explicite utilise `intent=record`, un jeton CSRF et un jeton de commande propre au panier. Elle persiste une commande **en attente de paiement**, sans envoyer de données au prestataire ni annoncer de prélèvement. Le panier est conservé. Le bouton de paiement reste désactivé ; la création locale d'une commande ne dépend pas de la disponibilité de CinetPay.

L'endpoint `app/payment-notify.php` répond en GET pour vérifier sa disponibilité. Il refuse les POST avec HTTP 503 tant que l'intégration n'est pas active ; il ne modifie jamais une commande dans cet état.

## Activer ultérieurement la connexion au prestataire

L'accord requis porte sur l'envoi à `https://api-checkout.cinetpay.com/v2/payment` des informations suivantes : référence de commande, montant en XOF, identifiant du compte, nom et prénom, courriel et, si renseignées, téléphone, adresse, ville, pays et code postal. Les identifiants d'API marchand authentifient cet échange côté serveur. Aucune carte, aucun CVV ni PIN Mobile Money ne doit être saisi ou conservé dans CyberShield.

Après cet accord, implémenter l'initialisation du checkout et la vérification sur l'API officielle v2, en conservant : HTTPS vérifié, hôtes fixes, absence de redirection serveur, délais bornés, taille de réponse bornée et aucune clé ou donnée personnelle dans les journaux. Activer un compte marchand CinetPay en XOF, configurer ses moyens de paiement et renseigner une origine HTTPS publique qui reçoit les notifications. `127.0.0.1` n'est pas joignable par le prestataire.

Variables prévues :

```dotenv
PAYMENT_ENABLED=false
APP_PUBLIC_URL=
CINETPAY_SITE_ID=
CINETPAY_API_KEY_FILE=
CINETPAY_SECRET_KEY_FILE=
```

Les alternatives `CINETPAY_API_KEY` et `CINETPAY_SECRET_KEY` sont lues côté serveur si aucun fichier n'est configuré. Les secrets ne doivent jamais être copiés dans un fichier versionné, du JavaScript ou la conversation. Un fichier secret absent ou illisible rend le paiement indisponible. Renseigner ces variables ne suffit pas à activer cette version.

## Installer les tables

Lancer le script CLI avec un compte autorisé à créer les tables, et les variables de connexion de la base applicative. Il n'accorde aucun privilège :

```powershell
php .\scripts\install-orders.php
```

Dans Docker, importer `database/orders.sql` dans la base existante avec le compte de migration. Ne pas supprimer le volume MariaDB et ne pas relancer l'initialisation complète. Les nouvelles installations peuvent importer ce SQL après `database/schema.sql`.

## Contrats pour l'interface

`new OrderService($conn)` expose `schemaInstalled()`, `createPending($userId, $cartItems, $checkoutToken, $customer)`, `findForUser($reference, $userId)`, `listForUser($userId, $limit)`, `items($orderId)` et `attachCheckout($orderId, $paymentUrl)`.

La page vérifie la disponibilité du schéma **avant** toute création locale. Elle ne doit ouvrir un guichet de paiement qu'après disponibilité du prestataire, actuellement désactivée. `createPending()` reçoit des articles `id` et `qty` ainsi qu'un jeton aléatoire de 64 caractères hexadécimaux conservé en session et renouvelé lors d'une modification du panier. Il n'utilise jamais les prix ni noms envoyés depuis le navigateur. Les coordonnées acceptées sont `name`, `email`, `phone`, `address`, `city`, `country` et `zip_code`. La commande est créée en transaction avec lecture du stock et des prix sous verrou. Le stock n'est pas réservé ni diminué à ce stade. Les tentatives identiques renvoient la même commande pour ce compte.

`findForUser()` limite la lecture au propriétaire. `items()` reçoit uniquement l'identifiant interne provenant de cette lecture ; ne pas accepter d'identifiant interne directement depuis une URL. La référence publique utilise 128 bits aléatoires et le préfixe `CS`.

L'interface publique affiche les prix et les totaux uniquement en **FCFA (XOF)**. Le catalogue existant et les instantanés `total_cents`/`currency=EUR` restent dans leur unité interne historique ; aucune migration ni réécriture des anciennes commandes n'est effectuée. `payment_amount` est le montant en XOF enregistré pour la commande et fait autorité pour son paiement.

Pour les **nouvelles commandes**, `StoreMoney` applique la parité **1 EUR = 655,957 XOF** et arrondit chaque prix unitaire au multiple de 5 XOF le plus proche. Le total est ensuite exactement la somme de ces unités arrondies multipliées par les quantités : une unité à 97 740 FCFA donne deux unités à **195 480 FCFA**. On ne reconvertit pas un total EUR, ce qui évite un écart entre la somme des prix affichés et le montant à régler. `cart_total_xof()` utilise le même calcul que `OrderService::createPending()`.

Les anciennes commandes conservent strictement leur `payment_amount`, y compris si leur conversion historique arrondissait le total. Une nouvelle consultation ou une répétition du jeton de commande ne change jamais ce montant. Le total d'une commande enregistrée doit toujours être affiché depuis `payment_amount`, sans recalcul depuis le catalogue courant.

## États et vérification financière

Le retour navigateur `/app/paiement.php?order=REFERENCE` ne constitue jamais une preuve de paiement. La future intégration doit vérifier le HMAC `x-token` sur la notification, avec les champs concaténés dans l'ordre officiel, et interroger `https://api-checkout.cinetpay.com/v2/payment/check` depuis le serveur. Vérifier le site marchand, la référence interrogée, la devise et le montant exact avant d'appeler `reconcilePayment()`.

`reconcilePayment()` est un service interne, jamais une route acceptant un statut du navigateur. Le statut `ACCEPTED` et le code `00`, sur montant et devise exacts, déclenchent une transaction qui verrouille la commande et les produits. Le stock est diminué une seule fois. Une répétition ou un refus tardif ne fait pas régresser une commande encaissée. `WAITING_FOR_CUSTOMER` reste en attente et `REFUSED` devient `payment_failed`.

Si un autre acheteur a épuisé le stock entre commande et confirmation financière, le paiement est conservé comme **`paid_review`**. Aucun stock ne devient négatif, aucun débit partiel du catalogue n'est effectué. Le marchand doit traiter ce cas : réapprovisionnement ou remboursement depuis le prestataire. Aucun remboursement automatique n'est implémenté. Les états ne prouvent ni livraison ni expédition ; ces opérations restent hors de ce périmètre.

## Vérification sans argent ni données persistantes

```powershell
php .\tests\store_money_test.php
php .\tests\orders_test.php
php .\tests\orders_test.php --database
```

Le premier mode teste les montants, URLs et signatures avec des valeurs factices. Le second utilise exclusivement des tables temporaires MariaDB/MySQL qui masquent les tables applicatives pendant la connexion, puis disparaissent à sa fermeture. Il vérifie idempotence, contrôle du propriétaire, falsification des prix et montants, attente opérateur, refus, stock et paiements répétés. Aucun appel réseau externe n'est exécuté et aucune commande commerciale n'est créée par ces tests.

## Sources officielles consultées

- [Initialisation CinetPay v2](https://docs.cinetpay.com/api/1.0-fr/checkout/initialisation) : guichet hébergé, devises, montant multiple de cinq et redirection.
- [Notifications CinetPay](https://docs.cinetpay.com/api/1.0-fr/checkout/notification) : contrôles serveur, répétitions et attente opérateur.
- [Signature HMAC CinetPay](https://docs.cinetpay.com/api/1.0-fr/checkout/hmac) : ordre des champs et comparaison HMAC SHA-256.
- [BCEAO, cours des devises contre franc CFA](https://www.bceao.int/index.php/fr/cours/cours-des-devises-contre-Franc-CFA-appliquer-aux-transferts) : parité de l'euro.
