# AutoGrep v2 — Architecture

## Vue d'ensemble

L'utilisateur donne son code en ZIP. AutoGrep identifie les dépendances vulnérables, génère une règle Semgrep par CVE, et renvoie les règles.

```
 Code ZIP (user)
      │
      ▼
┌────────────┐    ┌──────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐    ┌─────────┐
│ EXTRACT    │───▶│ DEP      │───▶│ GENERATE  │◀──▶│ CRITIC   │───▶│ EXECUTE  │───▶│ RETURN  │
│ /cachecode │    │ TRACK    │    │           │    │          │    │ Semgrep  │    │ règles  │
└────────────┘    └──────────┘    └─────▲─────┘    └──────────┘    └────┬─────┘    └─────────┘
                       │                │                               │
                       │ CVE list       │         ┌──────────┐          │
                       │                └─────────│ CLASSIFY │◀─────────┘
                       │                          │ ERROR    │
                       ▼                          └──────────┘
              Patch fetch
              (git commit)
```

Pipeline linéaire par CVE : **une CVE → une règle**. Le résultat final est l'ensemble des règles Semgrep validées.

Deux boucles de feedback pour la génération :

- **Boucle interne** (Critic → Generate) : le critic rejette la règle avant exécution. Feedback sémantique sur la qualité, le schéma, la pertinence.
- **Boucle externe** (Execute → Classify → Generate) : Semgrep a tourné, la règle est syntaxiquement OK mais ne matche pas correctement. Feedback factuel avec le code source et la sortie Semgrep.

---

## Flow utilisateur

### 1. Upload du code

L'utilisateur fournit son code source en archive ZIP. Le code est extrait dans `/cachecode`.

```
user_project.zip  →  /cachecode/user_project/
```

### 2. Dependency tracking

Analyse des fichiers de dépendances dans `/cachecode` pour identifier les CVEs :

| Ecosystème | Fichier analysé |
|------------|----------------|
| Python     | `requirements.txt`, `Pipfile.lock`, `poetry.lock` |
| Node.js    | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Go         | `go.sum` |
| Java       | `pom.xml`, `build.gradle` |
| PHP        | `composer.lock` |
| Ruby       | `Gemfile.lock` |
| Rust       | `Cargo.lock` |

Le dependency tracking agrège 3 sources de données CVE :

| Source | API | Ce qu'elle apporte |
|--------|-----|-------------------|
| **NVD** (NIST) | `services.nvd.nist.gov/rest/json/cves/2.0` | CWE, CVSS score, description officielle |
| **GitHub Advisory** | `api.github.com/advisories` | Commits de fix, packages affectés, écosystème |
| **OSV** (Google) | `api.osv.dev/v1/query` | Versions affectées, fix commits, couverture multi-écosystème |

Les 3 sources sont interrogées et les résultats sont agrégés : on prend le CWE de NVD, les commits de fix de GitHub Advisory / OSV, et les versions affectées d'OSV.

Output : liste de CVEs avec pour chacune le package affecté, la version vulnérable, le CWE, et le(s) commit(s) de fix.

### 3. Patch fetch

Pour chaque CVE, récupération du patch depuis le commit de fix :
- Clone/cache du repo source dans `cache/repos/`
- `git diff <parent>..<commit>` pour extraire le diff

### 4. Génération de règle (par CVE)

Le pipeline Generator → Critic → Execute produit une règle Semgrep validée. Détail dans les sections ci-dessous.

### 5. Résultat

Les règles Semgrep validées sont renvoyées à l'utilisateur. Chaque règle contient :
- L'ID de la CVE associée
- Le pattern Semgrep
- La sévérité (ERROR/WARNING/INFO)
- Le message explicatif
- Les métadonnées (CWE, package, langage)

---

## Concepts et patterns clés

### 1. Generator-Critic Pattern

Deux rôles LLM distincts avec des prompts et temperatures séparés.

**Generator** : créatif, produit la règle YAML. Temperature plus haute (0.3-0.5).
**Critic** : strict, évalue la règle sur plusieurs axes. Temperature basse (0.1-0.2).

Le critic évalue 3 axes :

| Axe | Ce qu'il vérifie | Exemple de rejet |
|-----|-------------------|------------------|
| **Structure** | YAML valide, champs requis, types corrects, id kebab-case, severity dans [ERROR/WARNING/INFO] | `severity: "CRITICAL"` → rejet |
| **Qualité** | Pattern pas trivial, utilise des metavariables, pas de code spécifique à un projet, pattern généralisable | `pattern: MyCompanyAuth.validate($X)` → rejet |
| **Pertinence** | Pattern correspond à la vulnérabilité, CWE cohérent, message décrit le risque | Rule pour XSS alors que la CVE est un buffer overflow → rejet |

Le critic répond avec un format structuré :

```
ACCEPT | REJECT
Score: 7/10
Axe structure: OK
Axe qualité: WARN — pattern trop spécifique, utilise une classe interne
Axe pertinence: OK
Suggestion: Remplacer `InternalValidator.check($X)` par un pattern générique `$OBJ.check($INPUT)`.
```

### 2. Multi-turn feedback (pas one-shot)

Chaque tentative précédente est ajoutée à l'historique des messages LLM :

```python
messages = [
    {"role": "system", "content": SYSTEM_PROMPT},
    {"role": "user",   "content": initial_prompt_with_cve_data},
    # Tentative 1
    {"role": "assistant", "content": "rules:\n- id: vuln-...\n  pattern: ..."},
    {"role": "user",     "content": "REJECT. Score 3/10. Pattern trop spécifique..."},
    # Tentative 2
    {"role": "assistant", "content": "rules:\n- id: vuln-...\n  pattern: ..."},
    {"role": "user",     "content": "REJECT. Score 6/10. Bon pattern mais false positive..."},
    # Tentative 3 → le LLM voit tout l'historique et corrige
]
```

### 3. Classification d'erreur typée

Après l'exécution Semgrep, l'erreur est classifiée. Chaque type a sa propre stratégie :

```
YAML_SYNTAX     → fix local en Python, pas de LLM (re-parse, fix indentation)
SCHEMA_INVALID  → fix local en Python (ajouter champs manquants, corriger types)
SEMGREP_ERROR   → feedback au generator avec le message d'erreur Semgrep exact
NO_MATCH_VULN   → feedback avec le code vulnérable qui devait matcher
FALSE_POSITIVE  → feedback avec le code fixé qui ne devait PAS matcher
PARSE_ERROR     → skip définitif (le fichier source n'est pas parsable)
```

Les deux premiers types ne rappellent JAMAIS le LLM. C'est du fix déterministe.

### 4. Temperature adaptative

```
Tentative 1 : 0.3 (conservateur)
Tentative 2 : 0.4 (un peu plus exploratoire)
Tentative 3 : 0.6 (créatif, essayer d'autres approches)

Après un REJECT du critic pour "trop spécifique" : baisser à 0.2
Après un NO_MATCH_VULN : monter à 0.5 (le pattern doit être plus large)
```

### 5. Budget de retries par type

Chaque type d'erreur a son propre budget :

```
critic_rejects     : max 3 allers-retours Generator ↔ Critic
semgrep_errors     : max 2 (si le pattern syntax est cassé 2 fois, abandonner)
no_match_vuln      : max 3 (le plus dur à résoudre)
false_positive     : max 2 (ajouter un pattern-not devrait suffire)
yaml/schema fixes  : max 2 (déterministe, si ça échoue 2 fois c'est foutu)
```

Total maximum absolu : 8 tentatives tous types confondus (circuit breaker).

---

## Stack technique

### Pourquoi LangGraph (et pas LangChain)

**LangChain** abstrait les appels LLM linéaires (prompt → call → parse) — ce que le code fait déjà.
**LangGraph** structure les workflows à boucles et branchements — ce qui manque au code actuel.

Le pipeline AutoGrep n'est pas une chaîne, c'est un graphe cyclique avec deux boucles de feedback. LangGraph modélise exactement ça.

```python
from langgraph.graph import StateGraph, END

graph = StateGraph(PipelineState)

graph.add_node("generate",  generate_node)
graph.add_node("critic",    critic_node)
graph.add_node("execute",   execute_node)
graph.add_node("classify",  classify_node)
graph.add_node("store",     store_node)

graph.set_entry_point("generate")
graph.add_edge("generate", "critic")

# Boucle interne : Critic décide
graph.add_conditional_edges("critic", route_after_critic, {
    "accepted":     "execute",
    "rejected":     "generate",
    "budget_spent": END,
})

graph.add_edge("execute", "classify")

# Boucle externe : Classification décide
graph.add_conditional_edges("classify", route_after_classify, {
    "success":       "store",
    "retry":         "generate",
    "fix_local":     "execute",
    "skip":          END,
    "budget_spent":  END,
})

graph.add_edge("store", END)

app = graph.compile(checkpointer=SqliteSaver(...))
```

Le `PipelineState` :

```python
class PipelineState(TypedDict):
    cve_id: str
    patch_diff: str                 # Diff du commit de fix
    repo_path: str                  # Chemin du repo cloné
    current_rule: Optional[dict]    # Règle YAML courante
    messages: list[dict]            # Historique multi-turn complet
    retry_budgets: dict[str, int]   # Compteurs par type d'erreur
    total_attempts: int             # Circuit breaker global
    critic_score: Optional[int]     # Dernier score du critic
    semgrep_result: Optional[dict]  # Dernière sortie Semgrep
    error_type: Optional[str]       # Dernier type d'erreur classifié
    temperature: float              # Temperature adaptative courante
```

### LLMs — appels directs aux APIs

Chaque provider est appelé directement via son SDK, sans intermédiaire.

| Rôle | Modèle recommandé | Provider | Pourquoi |
|------|-------------------|----------|----------|
| **Generator** | `deepseek-chat` ou `claude-sonnet-4-5-20250929` | DeepSeek / Anthropic | Doit produire du YAML Semgrep correct avec des patterns complexes |
| **Critic** | `claude-haiku-4-5-20251001` ou `gemini-2.0-flash` | Anthropic / Google | Jugement structuré, modèle rapide et cheap suffisant |

Configuration :

```python
@dataclass
class LLMConfig:
    # Generator
    generator_provider: str = "deepseek"        # deepseek | anthropic | openai
    generator_model: str = "deepseek-chat"
    generator_api_key: str = ""

    # Critic
    critic_provider: str = "anthropic"
    critic_model: str = "claude-haiku-4-5-20251001"
    critic_api_key: str = ""
```

Le code existant (`llm_provider.py`) supporte déjà les appels directs Anthropic, DeepSeek et OpenAI. Pas besoin de routeur intermédiaire.

### Monitoring : LangFuse (self-hosted)

Trace chaque appel LLM (latence, tokens, coût, prompt, réponse).

```python
from langfuse.callback import CallbackHandler

langfuse_handler = CallbackHandler(
    public_key="...", secret_key="...", host="http://localhost:3000"
)
result = app.invoke(initial_state, config={"callbacks": [langfuse_handler]})
```

Ce qu'on monitore :
- Coût réel par CVE
- Taux ACCEPT/REJECT du critic
- Nombre moyen de boucles avant convergence
- Comparaison de performance entre modèles

### Base de données : SQLite (ou PostgreSQL en prod)

Stocke l'état du pipeline et les résultats :
- Checkpointing LangGraph (reprise après crash)
- Historique des runs et tentatives
- Règles générées avec métadonnées

Pas besoin de vector DB. Pas de déduplication par embeddings. Le pipeline est linéaire : une CVE → une règle.

---

## Détail de chaque étape

### Step 1 — EXTRACT

**Input** : archive ZIP fournie par l'utilisateur
**Output** : code source extrait dans `/cachecode/`

```python
import zipfile

with zipfile.ZipFile(upload_path) as z:
    z.extractall("/cachecode/")
```

### Step 2 — DEPENDENCY TRACK

**Input** : code source dans `/cachecode/`
**Output** : liste de CVEs avec package, version vulnérable, CWE, commit(s) de fix

Détection des fichiers de dépendances, puis agrégation de 3 sources :

```python
# 1. OSV (Google) — versions affectées + fix commits
POST https://api.osv.dev/v1/query
{
    "package": {"name": "django", "ecosystem": "PyPI"},
    "version": "3.2.1"
}

# 2. GitHub Advisory — commits de fix + packages affectés
GET https://api.github.com/advisories?affects=django@3.2.1

# 3. NVD (NIST) — CWE, CVSS, description officielle
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-XXXXX
```

Les résultats sont agrégés : CWE et CVSS de NVD, commits de fix de GitHub Advisory / OSV, versions affectées d'OSV.

### Step 3 — PATCH FETCH

**Input** : commit de fix (depuis OSV/GitHub Advisory)
**Output** : diff du patch

```python
# Clone/cache le repo source
git clone https://github.com/{owner}/{repo} cache/repos/{owner}_{repo}

# Extraire le diff
git diff {parent_commit}..{fix_commit}
```

Les repos sont cachés dans `cache/repos/` pour ne pas recloner.

### Step 4 — GENERATE

**Input** : patch diff + feedback optionnel (du critic ou de l'exécution)
**Output** : règle Semgrep en YAML

Le prompt reçoit :
- La description de la CVE (depuis OSV)
- Le CWE (depuis OSV/NVD)
- Le diff du patch
- Les exemples Semgrep pour le langage cible
- L'historique complet des tentatives précédentes (multi-turn)

### Step 5 — CRITIC

**Input** : règle générée + données CVE
**Output** : ACCEPT/REJECT + score + feedback structuré

Si REJECT → feedback ajouté à l'historique, reboucle sur GENERATE.
Si ACCEPT → passe à EXECUTE.

### Step 6 — EXECUTE (validation)

**Input** : règle acceptée + repo source + patch info
**Output** : résultat Semgrep

Séquence :
1. Git checkout sur le parent du commit (code vulnérable)
2. `semgrep --config rule.yml --json target_file`
3. Git checkout sur le commit (code fixé)
4. `semgrep --config rule.yml --json target_file`

Critère de succès : `vuln_matches > 0 AND fixed_matches == 0`

### Step 7 — CLASSIFY ERROR

Purement déterministe, pas de LLM :

```
semgrep_errors contient "InvalidRuleSchema"  → SCHEMA_INVALID
semgrep_errors contient "PatternParseError"  → SEMGREP_ERROR
semgrep_errors contient "ParseError"         → PARSE_ERROR (skip)
vuln_matches == []                           → NO_MATCH_VULN
fixed_matches != []                          → FALSE_POSITIVE
```

### Step 8 — RETURN

**Input** : règle validée + métadonnées CVE
**Output** : règle Semgrep renvoyée à l'utilisateur

La règle finale est stockée et renvoyée. Le pipeline s'arrête ici — pas de scan du code utilisateur. C'est à l'utilisateur de lancer Semgrep avec les règles générées s'il le souhaite.

---

## La boucle de génération — pseudocode

```
function process_cve(cve_id, patch_diff, repo_path):
    feedback = null
    history = []

    for attempt in 1..MAX_ATTEMPTS:

        rule = generate(patch_diff, history, feedback)

        if rule is null:
            feedback = {type: "generation_failed", msg: "..."}
            continue

        // Boucle interne : Critic
        critic_result = critic(rule, cve_id)

        if critic_result.decision == REJECT:
            history.append(
                {role: "assistant", content: yaml(rule)},
                {role: "user",     content: critic_result.feedback}
            )
            feedback = {type: "critic_reject", detail: critic_result}
            continue

        // Le critic a ACCEPT → on exécute
        semgrep_result = execute_semgrep(rule, repo_path, patch_diff)
        error_type, error_msg = classify_error(semgrep_result)

        if error_type is null:
            store(rule, cve_id)
            return rule  // ← règle validée, renvoyée à l'utilisateur

        if error_type == PARSE_ERROR:
            return null  // non récupérable

        if error_type in [YAML_SYNTAX, SCHEMA_INVALID]:
            rule = fix_locally(rule, error_type, error_msg)
            continue

        // Boucle externe : feedback d'exécution
        history.append(
            {role: "assistant", content: yaml(rule)},
            {role: "user",     content: build_feedback(error_type, error_msg, semgrep_result)}
        )
        feedback = {type: error_type, detail: error_msg}
        continue

    return null  // budget épuisé
```

---

## Résumé de la stack

| Composant | Outil | Rôle |
|-----------|-------|------|
| Orchestration | **LangGraph** | State machine avec boucles, conditional edges, checkpointing |
| LLM Generator | **DeepSeek** / **Anthropic** (appels directs) | Génération de règles Semgrep |
| LLM Critic | **Anthropic** / **Google** (appels directs) | Evaluation qualité + pertinence |
| Monitoring | **LangFuse** (self-hosted) | Traces, tokens, coûts, scores |
| Database | **SQLite** (dev) / **PostgreSQL** (prod) | Runs, checkpoints, règles |
| Validation | **Semgrep CLI** | Exécution des règles sur le code |
| Git | **GitPython** | Clone, checkout, diff |
| CVE Data | **NVD** + **GitHub Advisory** + **OSV** | Dependency tracking agrégé, patch discovery |
| Code Input | **ZIP upload** → `/cachecode/` | Code utilisateur pour dependency tracking |
