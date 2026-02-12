# AutoGrep — Instructions IA

## Contexte

AutoGrep génère des règles Semgrep de sécurité à partir de CVE. Deux pipelines : **Pipeline 1** (patches MoreFixes → validation sur code réel) et **Pipeline 2** (Dependency-Track → enrichissement LLM → règle). Voir `ARCHITECTURE.md` pour les schémas et modules.

## Stack technique

- **Python 3.10+** — pas de framework web, CLI uniquement (argparse)
- **LLM** — OpenAI SDK via OpenRouter (modèle DeepSeek par défaut)
- **Semgrep CLI** — validation des règles sur code réel
- **GitPython** — clone/checkout des repos
- **SentenceTransformers** — embeddings pour dédup (all-MiniLM-L6-v2)
- **PyYAML** — parse/dump des règles Semgrep
- **requests** — client HTTP pour Dependency-Track API

## Commandes

```bash
# Pipeline 1 : générer des règles depuis les patches
python main.py --openrouter-api-key $KEY --patches-dir cvedataset-patches --output-dir generated_rules

# Pipeline 2 : générer des règles depuis Dependency-Track
python dt_pipeline.py --dt-url http://localhost:8081 --project-uuid UUID --llm-api-key $KEY

# Filtrer les règles générées (dédup + qualité)
python rule_filter.py --input-dir generated_rules --output-dir filtered_rules

# Tester une règle Semgrep manuellement
semgrep --config rule.yml --json target_file.py
```

## Conventions de code

- **Nommage** : snake_case partout (variables, fonctions, fichiers). Classes en PascalCase.
- **Dataclasses** : utiliser `@dataclass` pour les structures de données (pas de dicts bruts pour les entités).
- **Logging** : `logger = logging.getLogger(__name__)` en haut de chaque module. Pas de `print()` sauf dans le CLI final.
- **Types** : annoter les signatures de fonctions (`def foo(x: str) -> Optional[dict]:`).
- **Erreurs** : try/except ciblé au plus près de l'appel. Log + return None plutôt que crash.
- **Pas de state global** : tout passe par Config ou injection de dépendances via constructeur.

## Comment ajouter un module

1. Créer `nouveau_module.py` avec une classe principale
2. Le constructeur reçoit ce dont il a besoin (Config, client API, etc.)
3. Le module fait UNE chose (pas d'orchestration dans un module technique)
4. L'orchestrateur (main.py ou dt_pipeline.py) coordonne les appels
5. Ajouter les imports dans l'orchestrateur concerné

## Format des règles Semgrep en sortie

```yaml
rules:
  - id: vuln-<repo>-<commit8>       # ou dt-<component>-<cve>
    pattern: "<vulnerable pattern>"
    pattern-not: "<fixed pattern>"   # optionnel
    languages: ["python"]
    message: "Description de la vulnérabilité et comment la corriger"
    severity: ERROR                  # ERROR | WARNING | INFO
    metadata:
      category: security
      cwe: CWE-79
      source-url: "github.com/owner/repo/commit/abc123"
      technology: ["python"]
```

**Champs obligatoires** : `id`, `pattern` (ou `patterns`/`pattern-either`), `message`, `severity`, `languages`
**Champs recommandés** : `metadata.cwe`, `metadata.source-url`, `metadata.category`

## Pièges à éviter

- **YAML du LLM** : le LLM retourne souvent des blocs markdown (\`\`\`yaml). Toujours nettoyer avec `re.sub` les fences et les `<think>` tags avant de parser.
- **Thread safety** : CacheManager et RuleManager sont partagés entre threads dans Pipeline 1. Ajouter des locks si on modifie l'état partagé.
- **Git checkout concurrent** : deux threads ne doivent PAS checkout le même repo en parallèle. Le groupement par repo dans `main.py` protège contre ça.
- **Pagination DT** : l'API retourne max 100 résultats par défaut. Toujours utiliser `offset`/`limit` et vérifier `X-Total-Count`.
- **Retries LLM** : rendements décroissants après 3-5 tentatives. Inutile de retenter 20 fois.
- **Modèle hardcodé** : `llm_client.py:126` utilise `deepseek/deepseek-chat` en dur. Passer par config pour changer.
- **Règles trop spécifiques** : le LLM génère souvent des patterns liés à un projet précis. Le filtre qualité dans `rule_filter.py` est là pour ça — ne pas le contourner.
- **max_files_changed=1** : seuls les patches à 1 fichier sont traités. C'est voulu pour garder les patterns simples et ciblés.
