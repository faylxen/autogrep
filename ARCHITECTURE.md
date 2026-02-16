# AutoGrep v2 — Architecture d'industrialisation

## Vue d'ensemble

Pipeline automatisé : une CVE entre, une règle Semgrep validée sort.

```
CVE-ID
  │
  ▼
┌──────────┐    ┌───────────┐    ┌──────────┐    ┌──────────┐    ┌─────────┐
│ ENRICH   │───▶│ GENERATE  │◀──▶│ CRITIC   │───▶│ EXECUTE  │───▶│  STORE  │
│          │    │           │    │          │    │ Semgrep  │    │         │
└──────────┘    └─────▲─────┘    └──────────┘    └────┬─────┘    └─────────┘
                      │                               │
                      │         ┌──────────┐          │
                      └─────────│ CLASSIFY │◀─────────┘
                                │ ERROR    │
                                └──────────┘
```

Deux boucles de feedback distinctes :

- **Boucle interne** (Critic → Generate) : le critic rejette la règle avant exécution. Pas besoin de Semgrep, pas besoin de git checkout. Feedback sémantique sur la qualité, le schéma, la pertinence.
- **Boucle externe** (Execute → Classify → Generate) : Semgrep a tourné, la règle est syntaxiquement OK mais ne matche pas correctement. Feedback factuel avec le code source et la sortie Semgrep.

---

## Concepts et patterns clés

### 1. Generator-Critic Pattern

Le coeur de l'architecture. Deux rôles LLM distincts avec des prompts et temperatures séparés.

**Generator** : créatif, produit la règle YAML. Temperature plus haute (0.3-0.5).
**Critic** : strict, évalue la règle sur plusieurs axes. Temperature basse (0.1-0.2).

Le critic n'est PAS un simple validateur de schéma. C'est un juge qui évalue :

```
CRITIC = Schema Validation + Quality Assessment + Relevance Check
```

Les 3 axes du critic :

| Axe | Ce qu'il vérifie | Exemple de rejet |
|-----|-------------------|------------------|
| **Structure** | YAML valide, champs requis présents, types corrects, id en kebab-case, severity dans [ERROR/WARNING/INFO] | `severity: "CRITICAL"` → rejet |
| **Qualité** | Pattern pas trivial, utilise des metavariables, pas de code spécifique à un projet, pattern généralisable | `pattern: MyCompanyAuth.validate($X)` → rejet |
| **Pertinence** | Le pattern correspond bien à la vulnérabilité décrite dans l'enrichissement, le CWE est cohérent, le message décrit bien le risque | Rule pour XSS alors que la CVE est un buffer overflow → rejet |

Le critic répond avec un format structuré :

```
ACCEPT | REJECT
Score: 7/10
Axe structure: OK
Axe qualité: WARN — pattern trop spécifique, utilise une classe interne
Axe pertinence: OK
Suggestion: Remplacer `InternalValidator.check($X)` par un pattern générique `$OBJ.check($INPUT)` ou cibler la fonction stdlib sous-jacente.
```

Ce feedback structuré est renvoyé tel quel au generator comme message `user` dans l'historique conversationnel.

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
    {"role": "user",     "content": "REJECT. Score 6/10. Bon pattern mais false positive sur code fixé..."},
    # Tentative 3 → le LLM voit tout l'historique et corrige
]
```

Le LLM voit ses erreurs passées et les corrections demandées. Il converge au lieu de tourner en rond.

### 3. Classification d'erreur typée

Après l'exécution Semgrep, l'erreur est classifiée en types distincts. Chaque type a sa propre stratégie de retry :

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

Pas un compteur global. Chaque type d'erreur a son propre budget :

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

**LangChain : non pertinent ici.**
LangChain est une couche d'abstraction sur les appels LLM linéaires (prompt → call → parse).
Le code existant fait déjà ça directement via l'API OpenAI-compatible. LangChain ajouterait
de la complexité et des dépendances sans valeur — le pipeline n'est pas linéaire, c'est un
**graphe avec des cycles**. LangChain ne gère pas les boucles conditionnelles.

**LangGraph : directement pertinent.**
LangGraph est conçu pour les workflows **stateful avec des boucles et des branchements conditionnels**.
C'est exactement le pattern Generator ↔ Critic avec ses deux boucles de feedback.

Apports concrets de LangGraph pour ce projet :

| Feature LangGraph | Utilisation dans AutoGrep |
|-------------------|--------------------------|
| **State typé** (`TypedDict`) | L'état complet du pipeline (CVE enrichi, historique multi-turn, compteurs de retry par type, rule courante) vit dans un objet State unique, passé entre tous les nodes |
| **Conditional edges** | `critic_node` → si ACCEPT → `execute_node`, si REJECT → `generate_node`. Plus besoin de `while/if` manuels |
| **Checkpointing** | Si le pipeline crash (rate limit API, timeout git clone), il reprend exactement où il en était. Checkpointer PostgreSQL ou SQLite |
| **Subgraphs** | La boucle interne (Generator ↔ Critic) peut être un subgraph encapsulé, réutilisable et testable isolément |
| **Streaming** | Voir en temps réel ce que le generator produit, utile pour le debug |

Le graphe LangGraph :

```python
from langgraph.graph import StateGraph, END

graph = StateGraph(PipelineState)

graph.add_node("enrich",    enrich_node)
graph.add_node("generate",  generate_node)
graph.add_node("critic",    critic_node)
graph.add_node("execute",   execute_node)
graph.add_node("classify",  classify_node)
graph.add_node("store",     store_node)

graph.set_entry_point("enrich")
graph.add_edge("enrich", "generate")
graph.add_edge("generate", "critic")

# ── Boucle interne : Critic décide ──
graph.add_conditional_edges("critic", route_after_critic, {
    "accepted":     "execute",
    "rejected":     "generate",   # ← reboucle
    "budget_spent": END,
})

graph.add_edge("execute", "classify")

# ── Boucle externe : Classification décide ──
graph.add_conditional_edges("classify", route_after_classify, {
    "success":       "store",
    "retry":         "generate",   # ← reboucle avec feedback
    "fix_local":     "execute",    # ← re-execute sans re-generate
    "skip":          END,
    "budget_spent":  END,
})

graph.add_edge("store", END)

app = graph.compile(checkpointer=PostgresSaver(...))
```

Le `PipelineState` contient tout :

```python
class PipelineState(TypedDict):
    cve_id: str
    enriched: EnrichedCVE           # Données enrichies (NVD, OSV, patch, etc.)
    current_rule: Optional[dict]    # Règle YAML courante
    messages: list[dict]            # Historique multi-turn complet
    retry_budgets: dict[str, int]   # Compteurs par type d'erreur
    total_attempts: int             # Circuit breaker global
    critic_score: Optional[int]     # Dernier score du critic
    semgrep_result: Optional[dict]  # Dernière sortie Semgrep
    error_type: Optional[str]       # Dernier type d'erreur classifié
    temperature: float              # Temperature adaptative courante
```

### LLMs externes via OpenRouter

OpenRouter comme routeur unifié — une seule API, accès à tous les providers.
Le code existant utilise déjà `openai.OpenAI(base_url=openrouter_base_url)`, rien à changer côté client.

Choix des modèles par rôle :

| Rôle | Modèle recommandé | Pourquoi |
|------|-------------------|----------|
| **Generator** | `deepseek/deepseek-chat` ou `anthropic/claude-sonnet-4-5-20250929` | Doit produire du YAML Semgrep syntaxiquement correct avec des patterns complexes. Besoin de capacité de raisonnement sur le code |
| **Critic** | `anthropic/claude-haiku-4-5-20251001` ou `google/gemini-2.0-flash` | Jugement structuré, pas de génération complexe. Modèle rapide et cheap suffisant |
| **Enrichment summarizer** | `anthropic/claude-haiku-4-5-20251001` | Synthèse de texte, pas de code. Le plus cheap possible |
| **Embeddings** | `openai/text-embedding-3-small` via OpenAI direct | Meilleur rapport qualité/prix pour la déduplication |

Configuration :

```python
@dataclass
class LLMConfig:
    # OpenRouter pour les LLMs de génération/critique
    openrouter_api_key: str
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    generator_model: str = "deepseek/deepseek-chat"
    critic_model: str = "anthropic/claude-haiku-4-5-20251001"
    summarizer_model: str = "anthropic/claude-haiku-4-5-20251001"

    # OpenAI direct pour les embeddings (ou via OpenRouter)
    embedding_model: str = "text-embedding-3-small"
    embedding_api_key: str = ""  # si via OpenAI direct

    # Fallback : si un provider est down, OpenRouter route automatiquement
    # Mais on peut aussi configurer un fallback explicite :
    generator_fallback: str = "anthropic/claude-sonnet-4-5-20250929"
```

Avantage d'OpenRouter : **fallback automatique**. Si DeepSeek est down, on peut switcher
sur Claude Sonnet sans changer le code. Un seul `base_url`, une seule clé API.

Rate limiting : OpenRouter gère le rate limiting côté serveur. Côté client,
ajouter un simple retry exponentiel (déjà le pattern dans le code existant avec `max_retries`).

### Monitoring LLM : LangFuse (self-hosted via Docker)

Pourquoi : trace chaque appel LLM (latence, tokens, coût, prompt, réponse), versionne les prompts, permet de scorer les sorties.

```yaml
# docker-compose
services:
  langfuse:
    image: langfuse/langfuse:2
    ports: ["3000:3000"]
    depends_on: [postgres]
```

Intégration native avec LangGraph via le callback handler LangFuse.
Chaque node du graphe apparaît comme un span dans la trace.

```python
from langfuse.callback import CallbackHandler

langfuse_handler = CallbackHandler(
    public_key="...", secret_key="...", host="http://localhost:3000"
)

# Passer le handler à chaque invocation LangGraph
result = app.invoke(initial_state, config={"callbacks": [langfuse_handler]})
```

Ce qu'on monitore :
- **Coût réel par CVE** (OpenRouter renvoie le prix dans les headers)
- Taux ACCEPT/REJECT du critic (score dans LangFuse)
- Nombre moyen de boucles avant convergence
- Latence par node du graphe
- Prompts versionnés (A/B testing via LangFuse Prompt Management)
- Comparaison de performance entre modèles (DeepSeek vs Claude Sonnet en generator)

### Base de données : PostgreSQL + pgvector

Remplace les fichiers JSON/YAML actuels. Permet :
- Requêtes sur les règles par CVE, CWE, langage, score de qualité
- Déduplication par similarité vectorielle directement en SQL (`<=>` operator de pgvector)
- Historique de toutes les tentatives (pas juste le résultat final)
- Sert aussi de checkpointer pour LangGraph (persistence du state entre les runs)
- Partagé avec LangFuse (même instance PostgreSQL)

Tables essentielles : `cves`, `patches`, `rules`, `pipeline_runs`, `critic_evaluations`.

### Embeddings : pgvector + API externe

Remplace `sentence-transformers` en mémoire. Les embeddings sont :
1. Générés via l'API OpenAI (`text-embedding-3-small`, 1536 dims) ou OpenRouter
2. Stockés dans PostgreSQL (`vector(1536)`)
3. Comparés en SQL : `SELECT * FROM rules WHERE embedding <=> $1 < 0.1`

Plus besoin de charger un modèle en RAM pour la déduplication.

---

## Détail de chaque étape

### Step 1 — ENRICH

**Input** : un CVE-ID (ex: `CVE-2024-12345`)
**Output** : un objet enrichi avec toute la connaissance nécessaire

Sources de données (en priorité) :
1. **NVD API** (`services.nvd.nist.gov/rest/json/cves/2.0`) → CWE, CVSS, description, references
2. **OSV API** (`api.osv.dev/v1/vulns`) → packages affectés, versions, fix commits
3. **GitHub Advisory Database** (`gh api /advisories`) → liens vers les commits de fix
4. **Git diff** : depuis les URLs de commit trouvées dans les references → récupérer le patch réel
5. **Commit message** : `git log --format=%B -n 1 <commit>` → contexte du développeur
6. **LLM summarize** : synthétiser le tout en un résumé structuré (type de vuln, composant affecté, pattern de code dangereux)

Le CWE vient de NVD, pas du LLM. Le LLM ne devine plus le CWE.

Pour le full-local sans réseau, on peut pré-télécharger :
- NVD : dump JSON annuel (nvd.nist.gov/feeds)
- OSV : `gsutil cp -r gs://osv-vulnerabilities .`
- GitHub Advisory : clone `github/advisory-database`

### Step 2 — GENERATE

**Input** : objet CVE enrichi + feedback optionnel (du critic ou de l'exécution)
**Output** : une règle Semgrep en dict Python

Le prompt de génération reçoit :
- La description de la vulnérabilité (depuis l'enrichissement, pas juste le diff brut)
- Le CWE exact (depuis NVD)
- Le diff du patch
- Le commit message
- Les exemples Semgrep pour le langage cible
- L'historique complet des tentatives précédentes (multi-turn)

### Step 3 — CRITIC

**Input** : la règle générée + l'objet CVE enrichi
**Output** : ACCEPT/REJECT + score + feedback structuré par axe

Le critic a accès à l'enrichissement pour vérifier la pertinence (est-ce que la règle correspond bien à cette CVE ?).

Si REJECT → le feedback est ajouté à l'historique et on reboucle sur GENERATE.
Si ACCEPT → on passe à EXECUTE.

Le critic est un appel LLM séparé avec son propre system prompt orienté évaluation.

### Step 4 — EXECUTE

**Input** : règle acceptée par le critic + chemin du repo + info du patch
**Output** : résultat d'exécution Semgrep (matches vuln, matches fixed, erreurs)

Séquence :
1. Git checkout sur le parent du commit (code vulnérable)
2. `semgrep --config rule.yml --json target_file.ext`
3. Git checkout sur le commit (code fixé)
4. `semgrep --config rule.yml --json target_file.ext`
5. Collecter : vuln_matches, fixed_matches, semgrep_errors, stdout brut

Critère de succès : `len(vuln_matches) > 0 AND len(fixed_matches) == 0`

### Step 5 — CLASSIFY ERROR

**Input** : résultat d'exécution Semgrep
**Output** : type d'erreur (enum) + message

Purement déterministe, pas de LLM. C'est du pattern matching sur la sortie Semgrep :

```
semgrep_errors contient "InvalidRuleSchema"  → SCHEMA_INVALID
semgrep_errors contient "PatternParseError"  → SEMGREP_ERROR
semgrep_errors contient "ParseError"         → PARSE_ERROR (skip)
vuln_matches == []                           → NO_MATCH_VULN
fixed_matches != []                          → FALSE_POSITIVE
```

Le feedback renvoyé au generator est différent selon le type :
- **NO_MATCH_VULN** : inclut le code vulnérable qui devait matcher
- **FALSE_POSITIVE** : inclut le code fixé et la sortie Semgrep montrant les faux matches
- **SEMGREP_ERROR** : inclut le message d'erreur Semgrep exact

### Step 6 — STORE

**Input** : règle validée + CVE enrichi + résultat d'exécution
**Output** : écriture en base PostgreSQL + fichier YAML

On stocke :
- La règle finale
- L'embedding de la règle (pour déduplication future)
- Le mapping CVE ↔ règle
- Les métriques du run (nombre de tentatives, types d'erreurs, durée)

---

## La boucle complète — pseudocode

```
function process_cve(cve_id):
    enriched = enrich(cve_id)

    feedback = null
    history = []

    for attempt in 1..MAX_ATTEMPTS:

        rule = generate(enriched, history, feedback)

        if rule is null:
            feedback = {type: "generation_failed", msg: "..."}
            continue

        // ── Boucle interne : Critic ──
        critic_result = critic(rule, enriched)

        if critic_result.decision == REJECT:
            history.append({
                role: "assistant", content: yaml(rule),
                role: "user",     content: critic_result.feedback
            })
            feedback = {type: "critic_reject", detail: critic_result}
            continue   // ← reboucle sur generate SANS passer par semgrep

        // ── Le critic a ACCEPT → on exécute ──
        semgrep_result = execute_semgrep(rule, enriched.repo_path, enriched.patch)
        error_type, error_msg = classify_error(semgrep_result)

        if error_type is null:
            // ── SUCCES ──
            store(rule, cve_id, enriched, semgrep_result)
            return rule

        if error_type == PARSE_ERROR:
            return null  // non récupérable

        if error_type in [YAML_SYNTAX, SCHEMA_INVALID]:
            rule = fix_locally(rule, error_type, error_msg)
            // re-execute sans re-generate
            continue

        // ── Boucle externe : feedback d'exécution ──
        history.append({
            role: "assistant", content: yaml(rule),
            role: "user",     content: build_execution_feedback(error_type, error_msg, semgrep_result, enriched)
        })
        feedback = {type: error_type, detail: error_msg, semgrep_output: semgrep_result}
        continue   // ← reboucle sur generate avec le feedback d'exécution

    return null  // budget épuisé
```

---

## Résumé de la stack

| Composant | Outil | Rôle |
|-----------|-------|------|
| Orchestration / Graphe | **LangGraph** | State machine avec boucles, conditional edges, checkpointing |
| LLM Generator | **OpenRouter** → DeepSeek Chat / Claude Sonnet | Génération de règles Semgrep |
| LLM Critic | **OpenRouter** → Claude Haiku / Gemini Flash | Evaluation qualité + pertinence |
| Embeddings | **OpenAI** → text-embedding-3-small | Déduplication vectorielle |
| Monitoring | **LangFuse** (self-hosted) | Traces, tokens, coûts, scores, prompts |
| Database | **PostgreSQL + pgvector** | CVEs, rules, embeddings, runs, checkpoints |
| Validation | **Semgrep CLI** | Exécution des règles sur le code |
| Git | **GitPython** | Clone, checkout, diff |
| CVE Data | **NVD + OSV + GitHub Advisory** | Enrichissement |

### Pourquoi pas LangChain ?

Pour résumer la décision en une phrase :
**LangChain** abstrait les appels LLM linéaires (prompt → call → parse) — ce que le code fait déjà.
**LangGraph** structure les workflows à boucles et branchements — ce qui manque au code actuel.

Le pipeline AutoGrep n'est pas une chaîne, c'est un graphe cyclique. LangGraph modélise
exactement ça. LangChain serait une couche d'abstraction inutile par-dessus l'API OpenAI-compatible
déjà en place.
