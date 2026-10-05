# Scénarios du laboratoire SQLi

Les chaînes ci-dessous sont soumises à `security/lab.php`. Elles ne sont ni exécutées en base, ni écrites dans les journaux de production.

| Saisie pédagogique | Résultat visé |
|---|---|
| `' OR '1'='1' --` | Le moteur heuristique repère une tautologie et arrête l’analyse. |
| `' UNION SELECT username FROM users --` | Une signature UNION SELECT est bloquée immédiatement. |
| `admin' --` | La règle classe la saisie dans la zone grise et la transmet au MLP local. |
| `%2527%2520UNION%2520SELECT` | Le décodage URL borné reconnaît la forme encodée. |
| `Clavier mécanique pour l’école` | Aucun motif SQLi significatif ne doit être détecté. |
| `Bonjour -- merci pour votre réponse` | Le tiret dans un texte ordinaire ne suffit pas à déclencher un blocage. |
| `O'Connor` | Une apostrophe isolée n’est pas considérée comme une injection. |

Une décision d’autorisation du filtre ne dispense jamais l’application d’utiliser des requêtes préparées. Si le MLP manque ou ne répond pas pour une entrée de la zone grise, le middleware bloque par précaution.

Exécuter les contrôles automatisés décrits dans [README.md](../README.md) après l’installation locale.
