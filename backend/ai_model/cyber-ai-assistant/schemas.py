# schemas.py

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

# This class defines the structure for a single, standardized vulnerability.
class Vulnerability(BaseModel):
    cve_id: Optional[str] = None
    vulnerability_name: str
    description: str
    cvss_v3_score: Optional[float] = Field(None, ge=0, le=10)
    severity: str # e.g., 'Critical', 'High', 'Medium', 'Low', 'Info'
    affected_asset_ip: str
    affected_port: int
    protocol: str
    remediation: Optional[str] = "No remediation guidance available."
    exploit_available: bool = False
    source_tool: str # e.g., 'nmap', 'nuclei'

# This class defines the structure for the final, aggregated report.
class StandardizedReport(BaseModel):
    target: str
    scan_timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    vulnerabilities: List[Vulnerability]