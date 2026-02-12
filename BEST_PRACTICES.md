# AutoGrep — Bonnes pratiques & Patterns

## 1. Écriture de règles Semgrep

### Patterns de base
- **`pattern`** : match un code vulnérable. Utiliser `$VAR` (majuscules) pour les metavariables, `...` pour séquences de statements
- **`pattern-not`** : exclut le code fixé. S'applique APRÈS le match positif pour le filtrer
- **`pattern-inside`** : restreint le scope (ex: seulement dans une fonction/classe). Réduit les faux positifs
- **`pattern-not-inside`** : exclut un contexte (ex: code dans un bloc try/except de sanitization)

### Différence critique : `pattern-not` vs `pattern-not-inside`
- `pattern-not` : "ce code exact ne doit PAS matcher" — filtre sur le pattern lui-même
- `pattern-not-inside` : "le match ne doit PAS être à l'intérieur de ce bloc" — filtre sur le contexte englobant
- Exemple : détecter `eval($X)` mais PAS quand c'est dans un wrapper de sanitization → utiliser `pattern-not-inside`

### Taint mode (pour les injections)
- Activer avec `mode: taint` dans la règle
- Définir `pattern-sources` (entrée utilisateur) et `pattern-sinks` (fonction dangereuse)
- `pattern-sanitizers` pour les fonctions de nettoyage qui coupent la taint
- Les metavariables entre sources/sinks sont **indépendantes** par défaut. Utiliser `taint_unify_mvars: true` pour les unifier
- `by-side-effect: true` sur un source/sanitizer pour propager la taint au-delà de l'occurrence exacte

### Metavariables
- Format : `$MAJUSCULES` uniquement (`$X`, `$DATA`, `$FUNC`). Pas de minuscules (`$x` invalide)
- `focus-metavariable` : ne matche pas, redirige juste le finding vers la variable capturée
- `metavariable-pattern` : contraint une metavariable à matcher un sous-pattern
- `metavariable-regex` : contraint via regex
- Ne pas créer de metavariable inutile — si on ne la réutilise pas, un `...` suffit

### Métadonnées recommandées
- `cwe` : identifiant CWE (ex: CWE-79)
- `confidence` : high / medium / low
- `category` : toujours `security` pour nos règles
- `source-url` : lien vers le commit de fix

### Validation
- Toujours tester sur le code vulnérable ET le code fixé
- Règle valide = détecte le vuln, ne détecte PAS le fix
- Utiliser `semgrep --config rule.yml --json target.py` pour tester manuellement

## 2. Pipeline LLM — Génération de règles

### Feedback loop itératif
- **Compiler/valider → extraire erreur → renvoyer au LLM** : le pattern central du projet
- Pipeline 1 : semgrep valide la règle sur code réel, erreur renvoyée en prompt
- Pipeline 2 : validation YAML structurelle, retry si parsing échoue

### Rendements décroissants
- Les retries sont efficaces sur les 3-5 premières tentatives
- Au-delà, le LLM "tourne en rond" sur les mêmes erreurs
- Si ça échoue après max_retries → marquer comme processed et passer au suivant. Ne jamais boucler infiniment

### Prompt engineering pour Semgrep
- **Few-shot** : inclure 2-3 exemples de bonnes règles dans le prompt (par langage si possible)
- **Être explicite** : "Return ONLY raw YAML, no markdown fences" — le LLM ajoute des ``` par défaut
- **Inclure le diff** : plus le LLM a de contexte sur le fix, meilleure est la règle
- **Séparer enrichissement et génération** (Pipeline 2) : d'abord analyser le vuln en JSON structuré, puis générer la règle depuis le JSON. Plus fiable qu'un seul prompt monolithique

### Nettoyage de la sortie LLM
- Toujours supprimer `<think>...</think>` tags (modèles reasoning)
- Toujours supprimer les fences markdown (\`\`\`yaml ... \`\`\`)
- Toujours supprimer les marqueurs de document YAML (`---`, `...`)
- Parser avec `yaml.safe_load()` — jamais `yaml.load()`
- Valider le schéma après parsing (champs obligatoires : id, pattern, message, severity, languages)

### Structured output
- Utiliser `response_format={"type": "json_object"}` quand on attend du JSON (enrichissement)
- Ne PAS l'utiliser pour le YAML (pas supporté nativement)
- Toujours valider le JSON parsé contre un schéma attendu

## 3. Dependency-Track API

### Pagination
- **Défaut : 100 résultats max** par appel. Ne jamais supposer que c'est complet
- Utiliser `offset` et `limit` comme query params
- Lire le header `X-Total-Count` pour savoir combien de résultats existent au total
- Boucler : `offset=0, limit=100` → `offset=100, limit=100` → ... jusqu'à `offset >= X-Total-Count`

### Retry & rate limiting
- Retry avec backoff exponentiel : 2s, 4s, 8s, max 4 tentatives
- Cacher les résultats qui ne changent pas (vuln detail, references)
- Si DT renvoie 429 (rate limit), respecter `Retry-After` header si présent

### Endpoints utiles
- `GET /api/v1/finding/project/{uuid}` — tous les findings d'un projet
- `GET /api/v1/vulnerability/source/{source}/vuln/{vulnId}` — détail d'une vuln (references, CWE)
- Authentification : header `X-Api-Key`

## 4. Patterns Python généraux

### Séparation des responsabilités
- Un module = une responsabilité. Le client API ne fait PAS de logique métier
- L'orchestrateur (main.py, dt_pipeline.py) coordonne, les modules exécutent
- Injection de dépendances via constructeur : `def __init__(self, config, client)` — pas d'imports circulaires

### Gestion d'erreurs
- Try/except ciblé : capturer l'exception spécifique au plus près de l'appel
- Log l'erreur + return None/résultat par défaut — le pipeline continue
- Ne jamais silencer une exception (`except: pass`)
- Utiliser `exc_info=True` dans les logs pour garder la stacktrace

### Cache & idempotence
- Chaque opération coûteuse (clone git, appel LLM, appel API) doit vérifier le cache avant d'exécuter
- Le cache est un simple JSON sur disque — suffisant pour un CLI, pas besoin de Redis
- Marquer un item comme processed SEULEMENT après succès complet ou échec définitif

### Concurrence
- `ThreadPoolExecutor` avec max_workers borné (2-4 pour les appels réseau)
- Ne jamais modifier un état partagé (dict, list) depuis plusieurs threads sans lock
- Grouper le travail par unité indépendante (ex: par repo) pour minimiser les conflits
