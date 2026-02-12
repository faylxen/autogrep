# AutoGrep — Architecture cible

## Vue d'ensemble

AutoGrep génère automatiquement des règles Semgrep à partir de vulnérabilités connues (CVE).
Deux pipelines complémentaires alimentent le même format de sortie.

## Pipelines

### Pipeline 1 : Patch-based (existant, stable)

```
cvedataset-patches/*.patch
        │
        ▼
┌─────────────────┐     ┌──────────────┐
│ PatchProcessor   │────▶│ GitManager   │  clone/cache repo
│ parse diff,      │     │ checkout     │  checkout vuln/fix commits
│ detect language  │     └──────┬───────┘
└────────┬────────┘            │
         │                     ▼
         │            ┌─────────────────┐
         └───────────▶│  RuleValidator  │  test rule sur code vuln + fixé
                      │  (semgrep CLI)  │◀─── feedback erreur
                      └────────┬────────┘
                               │
         ┌─────────────────────┤
         ▼                     ▼
┌─────────────────┐   ┌──────────────┐
│  LLMClient      │   │ RuleManager  │  stockage mémoire + disque
│  génère YAML    │──▶│ par langue   │
│  retry+feedback │   └──────────────┘
└─────────────────┘
         │
         ▼
┌─────────────────┐
│  RuleFilter     │  dédup embeddings + éval qualité LLM
│  (post-process) │
└─────────────────┘
```

### Pipeline 2 : DT-based (nouveau)

```
Dependency-Track API
        │
        ▼
┌──────────────┐     ┌───────────────────┐
│  DtClient    │────▶│ MoreFixesLookup   │  CVE → patch dans dataset
│  findings +  │     │ CSV ou PostgreSQL  │
│  vuln detail │     └────────┬──────────┘
└──────┬───────┘              │
       │                      ▼
       │            ┌─────────────────────┐
       └───────────▶│ VulnerabilityEnricher│ LLM analyse toutes les sources
                    │  DT + MoreFixes +    │ → JSON structuré
                    │  NVD refs            │
                    └────────┬────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  DtPipeline     │ génère règle YAML
                    │  _generate_rule │ depuis données enrichies
                    │  _save_rule     │
                    └─────────────────┘
```

## Modules

| Module | Fichier | Rôle |
|--------|---------|------|
| **Config** | `config.py` | Dataclass de configuration + init CacheManager |
| **PatchProcessor** | `patch_processor.py` | Parse les fichiers .patch, extrait diffs par langage |
| **GitManager** | `git_manager.py` | Clone, cache et checkout des repos GitHub |
| **LLMClient** | `llm_client.py` | Appel LLM (OpenRouter), parse YAML, sanitize rules |
| **RuleValidator** | `rule_validator.py` | Exécute semgrep sur code vuln/fixé pour valider |
| **RuleManager** | `rule_manager.py` | Stockage rules en mémoire + persistance YAML par langue |
| **RuleFilter** | `rule_filter.py` | Dédup par embeddings cosine + éval qualité LLM |
| **CacheManager** | `cache_manager.py` | Cache persistant patches traités + repos échoués |
| **DtClient** | `dt_client.py` | Client REST Dependency-Track (findings, vuln detail) |
| **DtPipeline** | `dt_pipeline.py` | Orchestre Pipeline 2 : DT → enrich → règle |
| **VulnerabilityEnricher** | `vulnerability_enricher.py` | Synthèse LLM multi-sources → JSON structuré |
| **MoreFixesLookup** | `morefixes_lookup.py` | Lookup CVE dans MoreFixes (CSV/PostgreSQL) |
| **AutoGrep** | `main.py` | Orchestre Pipeline 1 : patches → règles |

## Structure répertoires

```
autogrep/
├── main.py                    # CLI Pipeline 1
├── dt_pipeline.py             # CLI Pipeline 2
├── config.py                  # Configuration partagée
│
├── patch_processor.py         # Parsing patches
├── git_manager.py             # Git operations
├── llm_client.py              # LLM pour Pipeline 1
├── rule_validator.py          # Validation semgrep
├── rule_manager.py            # Stockage règles
├── rule_filter.py             # Post-filtrage qualité
├── cache_manager.py           # Cache persistant
│
├── dt_client.py               # Client DT API
├── vulnerability_enricher.py  # Enrichissement LLM
├── morefixes_lookup.py        # Lookup MoreFixes
│
├── generated_rules/           # Sortie Pipeline 1 (brut)
│   └── <language>/            # Organisé par langage
├── filtered_rules/            # Sortie Pipeline 1 (filtré)
│   └── <language>/
├── dt_rules/                  # Sortie Pipeline 2
│   └── <language>/
│
├── cache/
│   ├── repos/                 # Clones git cachés
│   ├── processed_patches.json # Patches déjà traités
│   └── failed_repos.json      # Repos en échec
│
├── cvedataset-patches/        # Input : patches MoreFixes
├── requirements.txt
└── CLAUDE.md
```

## Principes d'architecture

1. **Idempotence** — Chaque patch/finding ne se traite qu'une fois (cache persistant). Relancer le pipeline reprend là où il s'est arrêté.
2. **Fail-fast avec retry** — Si le LLM génère du YAML invalide, on renvoie l'erreur en feedback. Max retries borné (3-8). Pas de retry infini.
3. **Séparation I/O / logique** — Les clients API (DtClient, OpenAI) sont isolés des orchestrateurs (AutoGrep, DtPipeline). Permet de mocker pour les tests.
4. **Un module = une responsabilité** — PatchProcessor ne génère pas de règles. LLMClient ne valide pas. RuleValidator ne stocke pas.
5. **Output déterministe** — Les règles sont toujours du YAML valide avec les champs : `id`, `pattern`/`patterns`, `message`, `severity`, `languages`, `metadata`.
6. **Données enrichies > prompts longs** — Pipeline 2 enrichit d'abord (JSON structuré), puis génère. Plus fiable que tout envoyer en un seul prompt.
