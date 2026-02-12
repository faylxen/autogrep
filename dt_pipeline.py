"""DT Pipeline: Dependency-Track finding → Enrich → Semgrep rule.

Unified pipeline that:
1. Fetches findings from Dependency-Track
2. Looks up each CVE in MoreFixes (adds context if found)
3. Fetches extended vuln detail from DT (references, etc.)
4. Enriches with LLM (analyzes ALL sources)
5. Generates a Semgrep rule from the enriched data
"""

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from openai import OpenAI

from dt_client import DtClient, DtFinding
from morefixes_lookup import MoreFixesLookup, MoreFixesResult
from vulnerability_enricher import EnrichedVulnerability, VulnerabilityEnricher

logger = logging.getLogger(__name__)


class DtPipeline:
    """Orchestrates: DT findings → enrich → Semgrep rules."""

    def __init__(
        self,
        dt_base_url: str,
        dt_api_key: str,
        llm_api_key: str,
        llm_base_url: str = "https://openrouter.ai/api/v1",
        llm_model: str = "deepseek/deepseek-chat",
        morefixes_csv: Optional[Path] = None,
        patches_dir: Optional[Path] = None,
        generated_rules_dir: Path = Path("generated_rules"),
        output_dir: Path = Path("dt_rules"),
        max_retries: int = 3,
    ):
        self.dt = DtClient(dt_base_url, dt_api_key)
        self.enricher = VulnerabilityEnricher(llm_api_key, llm_base_url, llm_model)
        self.morefixes = MoreFixesLookup(morefixes_csv, patches_dir)
        self.generated_rules_dir = generated_rules_dir
        self.output_dir = output_dir
        self.max_retries = max_retries

        self.llm_client = OpenAI(api_key=llm_api_key, base_url=llm_base_url)
        self.llm_model = llm_model

        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def run(self, project_uuid: str) -> List[Dict]:
        """Process all findings for a DT project."""
        findings = self.dt.get_findings(project_uuid)
        logger.info("Processing %d findings for project %s", len(findings), project_uuid)

        results = []
        for finding in findings:
            result = self.process_finding(finding)
            if result:
                results.append(result)

        logger.info(
            "Pipeline complete: %d/%d findings produced rules",
            len(results), len(findings),
        )
        return results

    # ------------------------------------------------------------------
    # Process a single finding
    # ------------------------------------------------------------------
    def process_finding(self, finding: DtFinding) -> Optional[Dict]:
        """Full pipeline for one finding: lookup → enrich → generate rule."""
        cve_id = finding.cve_id
        logger.info("=== Processing %s (%s %s) ===", cve_id, finding.component_name, finding.component_version)

        # -- Step 1: MoreFixes lookup --
        mf_result = self.morefixes.lookup(cve_id)
        if mf_result.found:
            # Check if a rule already exists
            best = mf_result.best_entry
            existing = self.morefixes.has_existing_rule(best, self.generated_rules_dir)
            if existing:
                logger.info("Existing rule found for %s: %s", cve_id, existing)
                return {
                    "cve_id": cve_id,
                    "status": "existing_rule",
                    "rule_path": str(existing),
                    "source": "morefixes-generated",
                }

        # -- Step 2: Get extended vuln detail from DT (references) --
        vuln_detail = self.dt.get_vulnerability_detail(finding.source, cve_id)

        # -- Step 3: LLM enrichment (always, regardless of MoreFixes) --
        enriched = self.enricher.enrich(finding, mf_result, vuln_detail)

        # -- Step 4: Generate Semgrep rule from enriched data --
        rule = self._generate_rule(enriched)
        if not rule:
            logger.warning("Failed to generate rule for %s", cve_id)
            return {
                "cve_id": cve_id,
                "status": "failed",
                "sources": enriched.sources_used,
            }

        # -- Step 5: Save rule --
        rule_path = self._save_rule(cve_id, rule, enriched)
        logger.info("Rule generated for %s: %s", cve_id, rule_path)

        return {
            "cve_id": cve_id,
            "status": "generated",
            "rule_path": str(rule_path),
            "sources": enriched.sources_used,
            "morefixes_found": mf_result.found,
            "vulnerability_type": enriched.vulnerability_type,
            "affected_function": enriched.affected_function,
        }

    # ------------------------------------------------------------------
    # Semgrep rule generation from enriched data
    # ------------------------------------------------------------------
    def _generate_rule(self, enriched: EnrichedVulnerability) -> Optional[dict]:
        """Generate a Semgrep rule using the enriched vulnerability data."""
        for attempt in range(self.max_retries):
            logger.info("Rule generation attempt %d/%d for %s",
                        attempt + 1, self.max_retries, enriched.cve_id)

            prompt = self._build_rule_prompt(enriched, attempt)
            try:
                response = self.llm_client.chat.completions.create(
                    model=self.llm_model,
                    messages=[
                        {"role": "system", "content": RULE_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.4,
                )
                content = response.choices[0].message.content
                if not content:
                    continue

                rule = self._parse_rule_yaml(content, enriched)
                if rule:
                    return rule

            except Exception as e:
                logger.error("Rule generation error (attempt %d): %s", attempt + 1, e)

        return None

    def _build_rule_prompt(self, enriched: EnrichedVulnerability, attempt: int) -> str:
        """Build the Semgrep rule generation prompt from enriched data."""
        cve_short = enriched.cve_id.replace("CVE-", "").replace("-", "")
        comp_clean = re.sub(r'[^a-z0-9]', '-', enriched.component.lower())
        suggested_id = f"dt-{comp_clean}-{cve_short}"

        parts = []
        parts.append(f"Generate a Semgrep rule for this vulnerability.\n")

        # -- Enriched analysis --
        parts.append(f"CVE: {enriched.cve_id}")
        parts.append(f"Component: {enriched.component} {enriched.version}")
        parts.append(f"Severity: {enriched.severity} (CVSS3: {enriched.cvss3_score})")
        if enriched.cwe_id:
            parts.append(f"CWE: {enriched.cwe_id} ({enriched.cwe_name})")

        parts.append(f"\nVulnerability type: {enriched.vulnerability_type}")
        parts.append(f"Root cause: {enriched.root_cause}")
        parts.append(f"Vulnerable pattern: {enriched.vulnerable_pattern}")
        parts.append(f"Affected function: {enriched.affected_function}")
        parts.append(f"Fix: {enriched.fix_description}")
        parts.append(f"Attack vector: {enriched.attack_vector}")
        parts.append(f"Exploitability: {enriched.exploitability}")

        # -- MoreFixes data (if present) --
        if enriched.diff:
            parts.append(f"\n--- Actual fix diff ---\n{enriched.diff[:3000]}")
        if enriched.vulnerable_method:
            parts.append(f"\nVulnerable method: {enriched.vulnerable_method}")
            parts.append(f"Method signature: {enriched.method_signature}")
        if enriched.code_before:
            parts.append(f"\nCode BEFORE fix (vulnerable):\n{enriched.code_before[:2000]}")
        if enriched.code_after:
            parts.append(f"\nCode AFTER fix (safe):\n{enriched.code_after[:2000]}")

        # -- References --
        if enriched.patch_urls:
            parts.append(f"\nPatch URLs: {', '.join(enriched.patch_urls[:5])}")

        # -- Rule requirements --
        parts.append(f"\n--- Generate the rule ---")
        parts.append(f"Rule ID: {suggested_id}")
        parts.append(f"""
Requirements:
1. The rule MUST detect the vulnerable pattern described above
2. Use pattern-not to exclude the fixed version when possible
3. Languages: detect from the component/code (or use 'generic')
4. Severity: map from {enriched.severity}
5. Include metadata: cwe, source-url, category: security

Return ONLY the YAML, no markdown fences, no explanation.""")

        if attempt > 0:
            parts.append(f"\nThis is retry #{attempt + 1}. Previous attempt failed. Be more careful with YAML syntax.")

        return "\n".join(parts)

    def _parse_rule_yaml(self, content: str, enriched: EnrichedVulnerability) -> Optional[dict]:
        """Parse LLM output into a valid Semgrep rule dict."""
        # Strip think tags and markdown
        content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)
        content = re.sub(r'^```ya?ml\s*', '', content, flags=re.MULTILINE)
        content = re.sub(r'^```\s*$', '', content, flags=re.MULTILINE)
        content = content.strip()

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            logger.error("YAML parse error: %s", e)
            return None

        if not isinstance(data, dict):
            return None

        # Unwrap rules list
        if "rules" in data and isinstance(data["rules"], list) and data["rules"]:
            rule = data["rules"][0]
        else:
            rule = data

        # Validate required fields
        if not rule.get("id"):
            cve_short = enriched.cve_id.replace("CVE-", "").replace("-", "")
            comp_clean = re.sub(r'[^a-z0-9]', '-', enriched.component.lower())
            rule["id"] = f"dt-{comp_clean}-{cve_short}"

        for field in ("message", "severity"):
            if field not in rule:
                if field == "severity":
                    rule["severity"] = "ERROR" if enriched.severity in ("CRITICAL", "HIGH") else "WARNING"
                else:
                    rule["message"] = f"{enriched.cve_id}: {enriched.vulnerability_type} in {enriched.component}"

        has_pattern = any(k in rule for k in ("pattern", "patterns", "pattern-either", "pattern-regex"))
        if not has_pattern:
            logger.error("Rule has no pattern field")
            return None

        # Ensure metadata
        meta = rule.setdefault("metadata", {})
        meta.setdefault("cve", enriched.cve_id)
        meta.setdefault("category", "security")
        if enriched.cwe_id:
            meta.setdefault("cwe", enriched.cwe_id)
        if enriched.fix_commit:
            meta.setdefault("fix-commit", enriched.fix_commit)
        meta.setdefault("sources", enriched.sources_used)
        if enriched.repo_url:
            meta.setdefault("source-url", f"{enriched.repo_url}/commit/{enriched.fix_commit}")

        return rule

    # ------------------------------------------------------------------
    # Save rule
    # ------------------------------------------------------------------
    def _save_rule(self, cve_id: str, rule: dict, enriched: EnrichedVulnerability) -> Path:
        """Save the generated rule to disk."""
        # Determine language subdirectory
        lang = "generic"
        if rule.get("languages") and isinstance(rule["languages"], list):
            lang = rule["languages"][0]

        lang_dir = self.output_dir / lang
        lang_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{rule['id']}.yml"
        rule_path = lang_dir / filename

        with open(rule_path, "w") as f:
            yaml.dump({"rules": [rule]}, f, sort_keys=False, default_flow_style=False)

        # Also save enrichment data alongside
        enrichment_path = lang_dir / f"{rule['id']}.enrichment.json"
        enrichment_data = {
            "cve_id": enriched.cve_id,
            "component": enriched.component,
            "version": enriched.version,
            "vulnerability_type": enriched.vulnerability_type,
            "root_cause": enriched.root_cause,
            "vulnerable_pattern": enriched.vulnerable_pattern,
            "affected_function": enriched.affected_function,
            "fix_description": enriched.fix_description,
            "sources_used": enriched.sources_used,
            "morefixes_confidence": enriched.morefixes_confidence,
            "fix_commit": enriched.fix_commit,
        }
        with open(enrichment_path, "w") as f:
            json.dump(enrichment_data, f, indent=2)

        return rule_path


# ------------------------------------------------------------------
# System prompt for rule generation
# ------------------------------------------------------------------
RULE_SYSTEM_PROMPT = """You generate Semgrep rules in YAML format from enriched vulnerability analyses.

You receive:
- CVE details (severity, CWE, description)
- LLM-analyzed vulnerability pattern, root cause, affected function
- Optionally: actual fix diff, vulnerable code, method signature from MoreFixes

Your job: produce a PRECISE Semgrep rule that detects the vulnerable pattern.

Rules:
1. Return ONLY raw YAML — no markdown fences, no explanation
2. Required fields: id, pattern (or patterns/pattern-either), message, severity, languages
3. Use pattern-not for the fixed version when you have the fix code
4. Use metavariables ($VAR) for flexible matching
5. Be specific enough to minimize false positives
6. Include metadata: cwe, category, source-url"""


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="DT Pipeline: Dependency-Track → LLM enrichment → Semgrep rules"
    )
    parser.add_argument("--dt-url", required=True, help="Dependency-Track base URL")
    parser.add_argument("--dt-api-key", default=os.environ.get("DT_API_KEY"), help="DT API key")
    parser.add_argument("--project-uuid", required=True, help="DT project UUID")
    parser.add_argument("--llm-api-key", default=os.environ.get("OPENROUTER_API_KEY"), help="LLM API key")
    parser.add_argument("--llm-base-url", default="https://openrouter.ai/api/v1")
    parser.add_argument("--llm-model", default="deepseek/deepseek-chat")
    parser.add_argument("--morefixes-csv", type=Path, default=None, help="Path to MoreFixes CSV export")
    parser.add_argument("--patches-dir", type=Path, default=Path("cvedataset-patches"))
    parser.add_argument("--generated-rules-dir", type=Path, default=Path("generated_rules"))
    parser.add_argument("--output-dir", type=Path, default=Path("dt_rules"))
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if not args.dt_api_key:
        print("ERROR: DT API key required (--dt-api-key or DT_API_KEY env)")
        sys.exit(1)
    if not args.llm_api_key:
        print("ERROR: LLM API key required (--llm-api-key or OPENROUTER_API_KEY env)")
        sys.exit(1)

    pipeline = DtPipeline(
        dt_base_url=args.dt_url,
        dt_api_key=args.dt_api_key,
        llm_api_key=args.llm_api_key,
        llm_base_url=args.llm_base_url,
        llm_model=args.llm_model,
        morefixes_csv=args.morefixes_csv,
        patches_dir=args.patches_dir,
        generated_rules_dir=args.generated_rules_dir,
        output_dir=args.output_dir,
        max_retries=args.max_retries,
    )

    results = pipeline.run(args.project_uuid)

    # Print summary
    generated = sum(1 for r in results if r["status"] == "generated")
    existing = sum(1 for r in results if r["status"] == "existing_rule")
    failed = sum(1 for r in results if r["status"] == "failed")
    print(f"\n{'='*60}")
    print(f"DT Pipeline Results:")
    print(f"  Generated:     {generated}")
    print(f"  Existing rule: {existing}")
    print(f"  Failed:        {failed}")
    print(f"{'='*60}")

    # Save full results
    results_path = args.output_dir / "pipeline_results.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Full results: {results_path}")


if __name__ == "__main__":
    main()
