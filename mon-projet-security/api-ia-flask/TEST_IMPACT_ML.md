# Tester l’impact réel de l’IA / ML

## 1. Tester l’API Flask seule (impact du modèle)

Objectif : voir la différence de **risk** et **confidence** avec ou sans le modèle ML.

### Avec le modèle (ML activé)

1. Dans `api-ia-flask`, lancer l’API :
   ```bash
   python app.py
   ```
2. Vérifier que le modèle est chargé : ouvrir http://127.0.0.1:5000/health  
   → `"ml_loaded": true`
3. Dans un **autre terminal**, lancer le script de test :
   ```bash
   cd api-ia-flask
   python test_ml_impact.py
   ```
4. Noter les valeurs **risk**, **confidence** et **ml_used: true** pour chaque entrée.

### Sans le modèle (règles seules)

1. Arrêter l’API (Ctrl+C).
2. Renommer le modèle pour le désactiver :
   ```bash
   ren model.joblib model.joblib.bak
   ```
3. Relancer l’API : `python app.py`  
   → http://127.0.0.1:5000/health donne `"ml_loaded": false`
4. Relancer : `python test_ml_impact.py`
5. Comparer les **risk** / **confidence** avec l’étape « Avec le modèle ».  
   Les différences montrent l’**impact du ML** (le modèle peut être plus précis que les règles sur la zone grise).

### Réactiver le modèle

```bash
ren model.joblib.bak model.joblib
```

---

## 2. Tester via l’application (login PHP)

Objectif : voir l’IA décider du **blocage** en conditions réelles.

### Quand l’IA est appelée

Le PHP n’appelle l’API Flask que si le score du détecteur est dans la **zone grise** :  
**30 ≤ score < 80** (après pondération par le contexte, ex. login × 1.3).

- Score **≥ 80** → blocage immédiat par le PHP (l’API n’est pas appelée).
- Score **< 30** → pas d’analyse IA.
- Score **entre 30 et 80** → envoi à l’API ; si **risk > 0.75** → blocage (« BLOCKED_BY_AI »).

### Étapes

1. **Démarrer l’API Flask** (avec `model.joblib`) :
   ```bash
   cd api-ia-flask
   python app.py
   ```
2. **Ouvrir la page de connexion** :  
   http://localhost/mon-projet-security/public/login.php (ou votre URL).
3. **Tester des entrées « zone grise »** (ex. dans identifiant ou mot de passe) :
   - `1 and 1=1`
   - `user' or 'a'='a`
   - `select from`
4. Si l’IA décide du blocage (**risk > 0.75**), vous obtenez la **page 403** (Requête bloquée).
5. **Vérifier que l’IA a bien été utilisée** :
   - Dans les **logs** (ex. `var/log/security*.log` ou journaux PHP) : chercher **BLOCKED_BY_AI** ou un message indiquant un blocage par l’analyse IA.
   - En base : dans `security_incidents`, les incidents bloqués par l’IA ont un type / une méthode qui reflète l’analyse IA (selon votre schéma).

### Comparer avec l’API arrêtée

1. Arrêter l’API Flask.
2. Refaire les mêmes tests sur la page de login.  
   Le PHP utilisera le **fallback** (ThreatIntelligenceEngine).  
   Vous pouvez obtenir des **décisions différentes** (blocage ou pas) par rapport au cas où l’API + ML sont actifs → c’est l’**impact réel de l’IA** dans le flux applicatif.

---

## 3. Résumé

| Test | Où | Ce que vous voyez |
|------|-----|-------------------|
| **API seule** | `python test_ml_impact.py` | risk, confidence, ml_used avec/sans modèle |
| **Santé API** | http://127.0.0.1:5000/health | ml_loaded true/false |
| **Login + zone grise** | Page login, entrées 30 ≤ score < 80 | Page 403 si risk > 0.75 (décision IA) |
| **Logs / BDD** | Fichiers de log, table security_incidents | BLOCKED_BY_AI, type d’incident |

Plus les **risk** diffèrent entre « avec ML » et « sans ML » sur des entrées ambiguës, plus l’**impact réel de l’IA** est visible.
