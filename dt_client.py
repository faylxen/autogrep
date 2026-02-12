"""Dependency-Track API client for fetching vulnerability findings."""

import logging
import requests
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)


@dataclass
class DtFinding:
    """Represents a single vulnerability finding from Dependency-Track."""
    cve_id: str
    source: str
    component_name: str
    component_version: str
    component_purl: str
    severity: str
    cvss3_score: Optional[float] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    cwe_id: Optional[int] = None
    cwe_name: Optional[str] = None
    description: str = ""
    aliases: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DtVulnDetail:
    """Extended vulnerability details from /api/v1/vulnerability."""
    cve_id: str
    references: List[Dict[str, str]] = field(default_factory=list)
    cwes: List[Dict[str, Any]] = field(default_factory=list)
    description: str = ""
    recommendation: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


class DtClient:
    """Client for Dependency-Track REST API."""

    def __init__(self, base_url: str, api_key: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "X-Api-Key": api_key,
            "Accept": "application/json",
        })

    def _get(self, path: str, params: Optional[dict] = None) -> Any:
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            logger.error("DT API request failed: %s %s -> %s", "GET", url, e)
            raise

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def get_findings(self, project_uuid: str) -> List[DtFinding]:
        """GET /api/v1/finding/project/{uuid} — all findings for a project."""
        data = self._get(f"/api/v1/finding/project/{project_uuid}")
        findings: List[DtFinding] = []
        for item in data:
            vuln = item.get("vulnerability", {})
            comp = item.get("component", {})

            cve_id = vuln.get("vulnId", "")
            # Skip non-CVE entries (e.g. GHSA-only) — they'll appear as aliases
            if not cve_id.startswith("CVE-"):
                continue

            aliases = []
            for alias in vuln.get("aliases", []):
                for key in ("cveId", "ghsaId", "sonatypeId", "osvId", "snykId"):
                    val = alias.get(key)
                    if val and val != cve_id:
                        aliases.append(val)

            cwes = vuln.get("cwes", [])
            cwe_id = cwes[0].get("cweId") if cwes else None
            cwe_name = cwes[0].get("name") if cwes else None

            findings.append(DtFinding(
                cve_id=cve_id,
                source=vuln.get("source", ""),
                component_name=comp.get("name", ""),
                component_version=comp.get("version", ""),
                component_purl=comp.get("purl", ""),
                severity=vuln.get("severity", ""),
                cvss3_score=vuln.get("cvssV3BaseScore"),
                epss_score=vuln.get("epssScore"),
                epss_percentile=vuln.get("epssPercentile"),
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                description=vuln.get("description", ""),
                aliases=aliases,
                raw=item,
            ))
        logger.info("Fetched %d CVE findings for project %s", len(findings), project_uuid)
        return findings

    # ------------------------------------------------------------------
    # Vulnerability detail (for references)
    # ------------------------------------------------------------------
    def get_vulnerability_detail(self, source: str, vuln_id: str) -> Optional[DtVulnDetail]:
        """GET /api/v1/vulnerability/source/{source}/vuln/{vulnId}."""
        try:
            data = self._get(f"/api/v1/vulnerability/source/{source}/vuln/{vuln_id}")
        except requests.RequestException:
            return None

        refs = []
        for ref in data.get("references", []):
            refs.append({
                "source": ref.get("source", ""),
                "url": ref.get("url", ""),
            })

        cwes = []
        for cwe in data.get("cwes", []):
            cwes.append({
                "cweId": cwe.get("cweId"),
                "name": cwe.get("name", ""),
            })

        return DtVulnDetail(
            cve_id=data.get("vulnId", vuln_id),
            references=refs,
            cwes=cwes,
            description=data.get("description", ""),
            recommendation=data.get("recommendation", ""),
            raw=data,
        )
