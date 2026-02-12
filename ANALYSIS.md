# Analyse complète d'AutoGrep

## Qu'est-ce qu'AutoGrep ?

AutoGrep est un outil qui utilise un LLM (DeepSeek via OpenRouter) pour **générer automatiquement des règles Semgrep** à partir de patches de vulnérabilités (CVE fix commits), puis les **valide** en les exécutant contre le code vulnérable et le code corrigé.

## Architecture et Pipeline

```
Patches CVE (dataset MoreFixes)
    │
    ▼
┌─────────────────────────────┐
│  patch_processor.py         │
│  Parse filename → owner,    │
│  repo, commit. Extrait les  │
│  diffs par fichier/langage  │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  git_manager.py             │
│  Clone/cache le repo GitHub │
│  Vérifie que le commit      │
│  existe                     │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  rule_validator.py          │
│  Vérifie si des règles      │
│  existantes détectent déjà  │
│  cette vulnérabilité        │
└────────────┬────────────────┘
             │ (Non détectée)
             ▼
┌─────────────────────────────┐
│  llm_client.py              │
│  Génère une règle Semgrep   │
│  via DeepSeek (OpenRouter)  │
│  Prompt avec contexte,      │
│  exemples, guide syntaxe    │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  rule_validator.py          │
│  1. Checkout version vuln   │
│  2. Run Semgrep (doit       │
│     détecter)               │
│  3. Checkout version fixée  │
│  4. Run Semgrep (ne doit    │
│     PAS détecter)           │
│                             │
│  ✗ → Retry avec feedback    │
│       (max 3-8 tentatives)  │
│  ✓ → Stockage de la règle  │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│  rule_filter.py             │
│  Post-filtrage:             │
│  - Déduplication par        │
│    embeddings (cosine >0.9) │
│  - Évaluation qualité par   │
│    LLM (reject project-     │
│    specific)                │
└────────────┬────────────────┘
             │
             ▼
        Règles finales
   (645 règles, 20+ langages)
```

## Résultats actuels

| Métrique | Valeur |
|----------|--------|
| Règles générées | 3 591 |
| Règles après filtrage | 645 |
| Taux de rejet | 82% |
| Langages couverts | 20+ |
| Code source | 1 769 lignes Python (9 fichiers) |

## Points Forts

### 1. Boucle de feedback LLM → Validation → Retry
Quand une règle échoue la validation, le message d'erreur est réinjecté dans le prompt pour la tentative suivante. Le LLM apprend de ses erreurs en temps réel.

### 2. Validation par ground truth
Les règles sont testées contre le vrai code vulnérable (commit parent) et le vrai fix (commit actuel). Une règle n'est acceptée que si elle détecte sur le vulnérable ET ne détecte pas sur le fixé.

### 3. Double filtrage qualité
- Déduplication par similarité sémantique (sentence-transformers, seuil cosinus 0.9)
- Évaluation par LLM pour rejeter les règles trop spécifiques à un projet

### 4. Système de cache
Les patches déjà traités et les repos en échec sont persistés, permettant de reprendre un traitement interrompu.

### 5. Résultat tangible
645 règles filtrées et utilisables dans Semgrep/Opengrep, couvrant 20+ langages.

## Points Faibles

### 1. Modèle LLM hardcodé
Le modèle (`deepseek/deepseek-chat`) est en dur dans `llm_client.py:126`. Pas de paramètre pour changer de modèle. Dépendance unique à OpenRouter.

### 2. Limitation `max_files_changed=1`
Seuls les patches modifiant un seul fichier sont traités. Beaucoup de vulnérabilités touchent plusieurs fichiers.

### 3. Aucun test
Zéro test unitaire, intégration, ou régression. Aucun filet de sécurité pour les modifications.

### 4. Pas de CI/CD ni packaging
Pas de Dockerfile, pas de pyproject.toml, pas de GitHub Actions. Installation manuelle uniquement.

### 5. Thread safety fragile
Le `CacheManager` et `RuleManager` sont partagés entre 2 threads sans mécanisme de verrouillage. Risque de corruption des fichiers JSON.

### 6. Traitement partiel multi-langages
Si un patch contient des fichiers dans plusieurs langages, seul le premier groupe de langue est traité (`patch_processor.py:260-261`).

### 7. Pas de rate limiting API
Aucune gestion de rate limiting sur les appels OpenRouter. Risque de blocage ou de dépassement de budget.

### 8. Exemples de prompt limités
Les exemples de règles Semgrep dans le prompt ne couvrent que Python, JavaScript et Java. Les 17+ autres langages n'ont aucun exemple.

### 9. Validation trop binaire
Pas de mesure de faux positifs sur un corpus large, ni de scoring de qualité, ni de benchmark de performance des règles.

### 10. Gestion Git non isolée
Les checkout de commits se font sur le même clone. Avec le parallélisme, risque de race condition sur l'état Git.

## Évaluation d'industrialisation

### Verdict : Possible, mais nécessite un refactoring conséquent

Le concept est validé par les résultats. Le code actuel est un **prototype de recherche fonctionnel**, pas un outil de production.

### Axes de travail pour industrialiser

| Axe | État actuel | Cible production |
|-----|-------------|-----------------|
| Tests | Aucun | Unitaires + intégration + benchmarks qualité |
| CI/CD | Aucun | Pipeline build/lint/test/deploy |
| Packaging | Aucun | Docker + pyproject.toml + CLI |
| Thread safety | Fragile | Locks, isolation repos par thread |
| Observabilité | Logs basiques | Métriques, dashboard, alertes |
| Multi-modèle | Hardcodé DeepSeek | Paramétrable (GPT-4, Claude, Llama, etc.) |
| Rate limiting | Aucun | Throttling API, gestion budget |
| Scalabilité | 2 threads | Queue de jobs (Celery/Redis) |
| Qualité règles | Binaire | Benchmark faux positifs, scoring |
| Interface | CLI only | API REST, intégration CI/CD |

### Réutilisable tel quel
- Logique de validation (checkout vulnérable/fixé + Semgrep)
- Concept de feedback loop LLM → validation → retry
- Pipeline de filtrage par embeddings
- Structure générale du workflow

### À réécrire
- Thread safety
- Gestion repos Git (isolation par job)
- Abstraction provider LLM
- Système de queue pour processing distribué
- Métriques et monitoring
