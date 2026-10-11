"""
WHAT: Reporting Domain Schema & Pydantic Data Models.
WHY: Strongly validates the JSON structure before report compilation.
OWNS: Validation rules, schema definitions, and default fallback handling.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict

class ExaminerInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str = Field(default="[Examiner Name Not Provided]")
    designation: str = Field(default="Digital Forensics & Incident Response Analyst")
    agency: str = Field(default="State Cyber Forensic Laboratory")
    id: str = Field(default="FSL-DFIR-OFFICER-01")
    phone: Optional[str] = None
    email: Optional[str] = None

class CaseInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str
    agency: str = Field(default="Cyber Crime Police Division")
    classification: str = Field(default="CONFIDENTIAL // LAW ENFORCEMENT & JUDICIAL PROCEEDINGS")
    examiner: ExaminerInfo = Field(default_factory=ExaminerInfo)
    report_ts_ist: str
    analysis_ts_utc: str
    fir_number: Optional[str] = "FIR-2026-CR-904"
    investigating_officer: Optional[str] = "Inspector Rajesh Kumar"

class EvidenceInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    filename: str
    size: str
    sha256: str
    md5: str
    os: str = "Windows 11 23H2 (x64)"
    arch: str = "x86_64"
    dump_ts: str
    source: str = "Physical RAM Acquisition (FTK Imager / WinPmem)"
    profile: Optional[str] = "Win11x64_23H2"

class EngineModule(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str
    category: str
    description: str
    verdict: str  # DETECTED / NOT DETECTED / UNKNOWN / CLEAN

class EngineInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str = "Compsognathus (Compy)"
    version: str = "2.0.0"
    build: str = "v2.0-PRO-BUILD-884"
    modules: List[EngineModule] = Field(default_factory=list)

class ScanCoverage(BaseModel):
    model_config = ConfigDict(extra="allow")
    modules_run: int = 12
    duration_seconds: float = 482.4
    processes_scanned: int = 148
    vads_examined: int = 18450
    threads_audited: int = 2140
    handles_inspected: int = 41200

class SummaryInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    verdict: str  # DETECTED / NOT DETECTED / UNKNOWN
    risk_score: int = Field(ge=0, le=100)
    counts_by_severity: Dict[str, int] = Field(default_factory=dict)
    key_findings: List[str] = Field(default_factory=list)
    business_impact: Optional[str] = None
    immediate_actions: List[str] = Field(default_factory=list)

class ProcessTreeNode(BaseModel):
    model_config = ConfigDict(extra="allow")
    pid: int
    ppid: int
    name: str
    path: str
    cmdline: Optional[str] = None
    create_time: str
    session: int = 1
    flags: List[str] = Field(default_factory=list)
    is_anomalous: bool = False
    anomaly_reason: Optional[str] = None

class PPIDAnomaly(BaseModel):
    model_config = ConfigDict(extra="allow")
    rule: str
    observed: str
    expected: str
    severity: str
    mitre: str
    details: Optional[str] = None

class HiddenProcess(BaseModel):
    model_config = ConfigDict(extra="allow")
    pid: int
    name: str
    seen_in: List[str]
    missing_from: List[str]
    method: str
    threads: int = 0
    risk: str = "CRITICAL"

class RootkitCheck(BaseModel):
    model_config = ConfigDict(extra="allow")
    check: str
    verdict: str  # DETECTED / NOT DETECTED / UNKNOWN
    details: str
    mitre: str = "T1014"

class MemoryRegionDetails(BaseModel):
    model_config = ConfigDict(extra="allow")
    base_address: str
    size: str
    protection: str
    vad_tag: str = "VadS"
    backing: str = "Unbacked / Private Memory"
    entropy: float = 7.42
    thread_count: int = 1
    thread_start: Optional[str] = None

class FindingProcess(BaseModel):
    model_config = ConfigDict(extra="allow")
    pid: int
    ppid: int
    name: str
    path: str
    cmdline: Optional[str] = None
    create_time: str
    session: int = 1
    user: str = "NT AUTHORITY\\SYSTEM"

class DetailedFinding(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str
    title: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    confidence: float
    verdict: str  # DETECTED / UNKNOWN / NOT DETECTED
    mitre: List[str] = Field(default_factory=list)
    description: str
    process: FindingProcess
    memory_region: Optional[MemoryRegionDetails] = None
    artifacts: Dict[str, Any] = Field(default_factory=dict)
    iocs: Dict[str, Any] = Field(default_factory=dict)
    reasoning: List[str] = Field(default_factory=list)
    remediation: List[str] = Field(default_factory=list)
    why_it_matters: Optional[str] = None

class MitreEntry(BaseModel):
    model_config = ConfigDict(extra="allow")
    tactic: str
    technique_id: str
    technique_name: str
    finding_ref: str
    evidence: str

class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="allow")
    timestamp_utc: str
    source: str
    action: str
    entity: str
    significance: str
    severity: str = "INFO"

class RecommendationItem(BaseModel):
    model_config = ConfigDict(extra="allow")
    phase: str  # Immediate (0-4h) / Short-term (24-48h) / Long-term (30d)
    action: str
    owner: str
    effort: str
    regulatory_impact: str

class CandidateWorksheetItem(BaseModel):
    model_config = ConfigDict(extra="allow")
    candidate_id: str
    hypothesis: str
    unresolved_reason: str
    required_evidence: str
    checklist: List[str] = Field(default_factory=list)

class CustodyRecord(BaseModel):
    model_config = ConfigDict(extra="allow")
    item_num: int
    transferred_from: str
    transferred_to: str
    timestamp_utc: str
    purpose: str
    hash_verified: bool = True

class LedgerRecord(BaseModel):
    model_config = ConfigDict(extra="allow")
    n: int
    ts: str
    action: str
    hash: str
    prev_hash: str

class ForensicReportModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    case: CaseInfo
    evidence: EvidenceInfo
    engine: EngineInfo = Field(default_factory=EngineInfo)
    summary: SummaryInfo
    coverage: ScanCoverage = Field(default_factory=ScanCoverage)
    process_tree: List[ProcessTreeNode] = Field(default_factory=list)
    ppid_anomalies: List[PPIDAnomaly] = Field(default_factory=list)
    hidden_processes: List[HiddenProcess] = Field(default_factory=list)
    rootkit_checks: List[RootkitCheck] = Field(default_factory=list)
    findings: List[DetailedFinding] = Field(default_factory=list)
    mitre_mapping: List[MitreEntry] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    recommendations: List[RecommendationItem] = Field(default_factory=list)
    candidate_worksheet: Optional[List[CandidateWorksheetItem]] = None
    custody: List[CustodyRecord] = Field(default_factory=list)
    ledger: List[LedgerRecord] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
