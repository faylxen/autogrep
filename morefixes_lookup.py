"""Lookup CVEs in the MoreFixes dataset.

Supports two backends:
  1. CSV file (exported from MoreFixes PostgreSQL DB) — no DB required
  2. Direct PostgreSQL query (if DB is running)

CSV format expected (header row):
  cve_id,fix_commit,repo_url,confidence,commit_message,patched_file,
  diff,code_before,code_after,programming_language,
  vulnerable_method,method_signature,parameters,method_code,
  before_change,cwe_id,cwe_name,cwe_description
"""

import csv
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class MoreFixesEntry:
    """One CVE-to-fix mapping from MoreFixes."""
    cve_id: str
    fix_commit: str
    repo_url: str
    confidence: int = 0
    commit_message: str = ""
    patched_file: str = ""
    diff: str = ""
    code_before: str = ""
    code_after: str = ""
    programming_language: str = ""
    vulnerable_method: str = ""
    method_signature: str = ""
    parameters: str = ""
    method_code: str = ""
    before_change: Optional[bool] = None
    cwe_id: str = ""
    cwe_name: str = ""
    cwe_description: str = ""

    @property
    def patch_filename(self) -> str:
        """Derive the MoreFixes patch filename from repo_url + commit."""
        # https://github.com/aio-libs/aiohttp  →  github.com_aio-libs_aiohttp
        url = self.repo_url.replace("https://", "").replace("http://", "")
        url = url.rstrip("/").replace("/", "_")
        return f"{url}_{self.fix_commit}.patch"

    @property
    def is_high_confidence(self) -> bool:
        """Score 1337 = NVD-referenced, >=65 = Prospector-confirmed."""
        return self.confidence >= 65


@dataclass
class MoreFixesResult:
    """All MoreFixes entries for a single CVE (can have multiple fix commits)."""
    cve_id: str
    entries: List[MoreFixesEntry] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return len(self.entries) > 0

    @property
    def best_entry(self) -> Optional[MoreFixesEntry]:
        """Return the highest-confidence entry."""
        if not self.entries:
            return None
        return max(self.entries, key=lambda e: e.confidence)


class MoreFixesLookup:
    """Look up CVEs in the MoreFixes dataset."""

    def __init__(self, csv_path: Optional[Path] = None, patches_dir: Optional[Path] = None):
        self._index: Dict[str, List[MoreFixesEntry]] = {}
        self.patches_dir = patches_dir
        if csv_path and csv_path.exists():
            self._load_csv(csv_path)
            logger.info("MoreFixes CSV loaded: %d CVEs indexed", len(self._index))
        else:
            logger.warning("No MoreFixes CSV found at %s — lookup disabled", csv_path)

    # ------------------------------------------------------------------
    # CSV loading
    # ------------------------------------------------------------------
    def _load_csv(self, csv_path: Path):
        """Load the exported CSV into an in-memory index keyed by cve_id."""
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id = row.get("cve_id", "").strip()
                if not cve_id:
                    continue

                confidence_raw = row.get("confidence", "0")
                try:
                    confidence = int(confidence_raw)
                except ValueError:
                    confidence = 0

                before_raw = row.get("before_change", "")
                before_change = None
                if before_raw.lower() in ("true", "t", "1"):
                    before_change = True
                elif before_raw.lower() in ("false", "f", "0"):
                    before_change = False

                entry = MoreFixesEntry(
                    cve_id=cve_id,
                    fix_commit=row.get("fix_commit", "").strip(),
                    repo_url=row.get("repo_url", "").strip(),
                    confidence=confidence,
                    commit_message=row.get("commit_message", "").strip(),
                    patched_file=row.get("patched_file", "").strip(),
                    diff=row.get("diff", ""),
                    code_before=row.get("code_before", ""),
                    code_after=row.get("code_after", ""),
                    programming_language=row.get("programming_language", "").strip(),
                    vulnerable_method=row.get("vulnerable_method", "").strip(),
                    method_signature=row.get("method_signature", "").strip(),
                    parameters=row.get("parameters", "").strip(),
                    method_code=row.get("method_code", ""),
                    before_change=before_change,
                    cwe_id=row.get("cwe_id", "").strip(),
                    cwe_name=row.get("cwe_name", "").strip(),
                    cwe_description=row.get("cwe_description", ""),
                )
                self._index.setdefault(cve_id, []).append(entry)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def lookup(self, cve_id: str) -> MoreFixesResult:
        """Look up a CVE and return all matching MoreFixes entries."""
        entries = self._index.get(cve_id, [])
        result = MoreFixesResult(cve_id=cve_id, entries=entries)
        if result.found:
            best = result.best_entry
            logger.info(
                "MoreFixes HIT: %s → commit %s (confidence %d, method: %s)",
                cve_id, best.fix_commit[:12], best.confidence,
                best.vulnerable_method or "N/A",
            )
        else:
            logger.debug("MoreFixes MISS: %s", cve_id)
        return result

    def has_patch_file(self, entry: MoreFixesEntry) -> Optional[Path]:
        """Check if the actual .patch file exists on disk."""
        if not self.patches_dir:
            return None
        patch_path = self.patches_dir / entry.patch_filename
        return patch_path if patch_path.exists() else None

    def has_existing_rule(self, entry: MoreFixesEntry, generated_rules_dir: Path) -> Optional[Path]:
        """Check if a Semgrep rule was already generated for this commit."""
        if not entry.programming_language:
            return None
        lang = entry.programming_language.lower()
        # Rules are named like vuln-REPONAME-COMMIT8.yml
        repo_name = entry.repo_url.rstrip("/").rsplit("/", 1)[-1].lower()
        commit_short = entry.fix_commit[:8]
        rule_name = f"vuln-{repo_name}-{commit_short}.yml"
        rule_path = generated_rules_dir / lang / rule_name
        return rule_path if rule_path.exists() else None
