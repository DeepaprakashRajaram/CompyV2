"""
WHAT: Evidence-Linked Mitigation & Response Recommendation Engine.
WHY: Transforms verified memory forensic observations into practical, prioritized,
     non-destructive guidance for incident responders.
OWNS: Mitigation recommendation generation, priority ranking, and response categorization.
DOES NOT OWN: Destructive host actions, active containment execution.
INVARIANTS:
  - Every recommendation is strictly linked to a concrete finding or evidence ID.
  - Distinguishes recommended actions from actions executed by Compy.
  - Requires human authorization for containment or disruptive responses.
  - Never generates recommendations from fabricated data.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple

from fmd.v2.domain.contracts import EvidenceId, IObservation
from fmd.v2.domain.reasoning.investigation import InvestigationDossier

class MitigationPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class MitigationActionType(str, Enum):
    INVESTIGATIVE = "INVESTIGATIVE"
    PREVENTIVE = "PREVENTIVE"
    CONTAINMENT = "CONTAINMENT"

@dataclass(frozen=True)
class MitigationRecommendation:
    """Actionable, evidence-linked response guidance for incident responders."""
    recommendation_id: str
    target_evidence_id: str
    finding_title: str
    priority: MitigationPriority
    action_type: MitigationActionType
    reason: str
    recommended_action: str
    human_authorization_required: bool
    prerequisites: str
    limitations: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "target_evidence_id": self.target_evidence_id,
            "finding_title": self.finding_title,
            "priority": self.priority.value,
            "action_type": self.action_type.value,
            "reason": self.reason,
            "recommended_action": self.recommended_action,
            "human_authorization_required": self.human_authorization_required,
            "prerequisites": self.prerequisites,
            "limitations": self.limitations
        }


class MitigationEngine:
    """
    Evaluates forensic findings in an InvestigationDossier and produces
    prioritized, actionable mitigation recommendations.
    """

    @classmethod
    def generate_recommendations(cls, dossier: InvestigationDossier) -> List[MitigationRecommendation]:
        recs: List[MitigationRecommendation] = []
        rec_counter = 1

        # Flatten observations across candidates
        observations: List[IObservation] = []
        for candidate in dossier.candidates:
            if hasattr(candidate, "related_observations"):
                observations.extend(candidate.related_observations)
            elif hasattr(candidate, "observations"):
                observations.extend(candidate.observations)

        seen_targets: Set[Tuple[str, str]] = set()

        for obs in observations:
            category = getattr(obs, "anomaly_category", "")
            target_id = str(obs.target_evidence_id) if hasattr(obs, "target_evidence_id") else "EVID-UNKNOWN"
            desc = getattr(obs, "description", "")

            # 1. Code Injection / Unbacked Memory Allocation
            if category == "CODE_INJECTION" or hasattr(obs, "start_address"):
                pid = getattr(obs, "process_pid", 0)
                pname = getattr(obs, "process_name", "unknown")
                prot = getattr(obs, "protection", "PAGE_EXECUTE_READWRITE")
                dedup_key = ("CODE_INJECTION", target_id)
                if dedup_key not in seen_targets:
                    seen_targets.add(dedup_key)
                    recs.append(MitigationRecommendation(
                        recommendation_id=f"REC-{rec_counter:03d}",
                        target_evidence_id=target_id,
                        finding_title=f"Injected Executable Memory in PID {pid} ({pname})",
                        priority=MitigationPriority.CRITICAL if "MZ" in desc or "PE" in desc else MitigationPriority.HIGH,
                        action_type=MitigationActionType.CONTAINMENT,
                        reason=(
                            f"Process {pname} (PID {pid}) contains unbacked executable/writable memory ({prot}). "
                            "Indicates potential reflective DLL loading, process hollowing, or in-memory shellcode."
                        ),
                        recommended_action=(
                            "1. If host is active, isolate endpoint from production network to prevent lateral movement. "
                            f"2. Acquire full VAD memory dump and handle table for PID {pid}. "
                            "3. Do not terminate process until parent-child context and network sockets are recorded. "
                            "4. Inspect memory buffer for embedded C2 configuration and PE headers."
                        ),
                        human_authorization_required=True,
                        prerequisites="Authorized incident responder approval for endpoint containment.",
                        limitations="JIT runtimes (.NET, browser engines) allocate RWX pages; corroborate unbacked status."
                    ))
                    rec_counter += 1

            # 2. Hidden Process / DKOM Discrepancy
            elif category in ("ROOTKIT_DKOM", "HIDDEN_PROCESS", "UNLINKED_PROCESS_DISCREPANCY") or hasattr(obs, "discrepancy_type"):
                pid = getattr(obs, "process_pid", 0)
                pname = getattr(obs, "process_name", "unknown")
                dedup_key = ("HIDDEN_PROCESS", target_id)
                if dedup_key not in seen_targets:
                    seen_targets.add(dedup_key)
                    recs.append(MitigationRecommendation(
                        recommendation_id=f"REC-{rec_counter:03d}",
                        target_evidence_id=target_id,
                        finding_title=f"Hidden/Unlinked Process Object: {pname} (PID {pid})",
                        priority=MitigationPriority.HIGH,
                        action_type=MitigationActionType.INVESTIGATIVE,
                        reason=(
                            f"Process {pname} (PID {pid}) was found in pool scan (psscan) but absent from active list (pslist). "
                            "May indicate Direct Kernel Object Manipulation (DKOM) or unlinked terminated process."
                        ),
                        recommended_action=(
                            "1. Query Windows Security Event Logs (Event ID 4688/4689) for matching PID and start/exit timestamps. "
                            "2. Preserve raw memory dump and pagefile for kernel rootkit and hook analysis. "
                            "3. If host is active, perform out-of-band kernel integrity verification (PatchGuard / DSE)."
                        ),
                        human_authorization_required=True,
                        prerequisites="Access to Windows Security Event logs and kernel forensic symbols.",
                        limitations="Terminated processes whose objects remain in unallocated pool memory can trigger discrepancies."
                    ))
                    rec_counter += 1

            # 3. Process Tree Anomaly / Suspicious Spawn / Encoded Cmdline
            elif category in (
                "PROCESS_TREE_ANOMALY", "SUSPICIOUS_SPAWN", "ENCODED_CMDLINE", 
                "PPID_SPOOFING", "EXPLOIT_SPAWN", "SYSTEM_MASQUERADE", "LOLBAS_ANOMALY", "SUSPICIOUS_CMDLINE",
                "SUSPICIOUS_COMMAND_LINE", "PROCESS_LINEAGE_ANOMALY"
            ) or hasattr(obs, "expected_parent"):
                pid = getattr(obs, "process_pid", 0)
                pname = getattr(obs, "process_name", "unknown")
                dedup_key = ("PROCESS_TREE", target_id)
                if dedup_key not in seen_targets:
                    seen_targets.add(dedup_key)
                    recs.append(MitigationRecommendation(
                        recommendation_id=f"REC-{rec_counter:03d}",
                        target_evidence_id=target_id,
                        finding_title=f"Suspicious Process Ancestry or Command Line: {pname} (PID {pid})",
                        priority=MitigationPriority.HIGH,
                        action_type=MitigationActionType.INVESTIGATIVE,
                        reason=(
                            f"Anomalous process tree or suspicious command-line execution detected: {desc}."
                        ),
                        recommended_action=(
                            "1. Extract and decode the full command line in an isolated sandbox environment. "
                            "2. Identify referenced URLs, IPs, or scripts without querying them from production systems. "
                            "3. Query proxy and DNS logs for connections initiated by this process. "
                            "4. Review user account privileges under which the command executed."
                        ),
                        human_authorization_required=False,
                        prerequisites="Isolated analysis environment and network proxy/DNS logging.",
                        limitations="Legitimate IT administration scripts may use encoded commands or LOLBAS utilities."
                    ))
                    rec_counter += 1

            # 4. YARA Signature Match
            elif category == "YARA_RULE_MATCH" or hasattr(obs, "rule_name"):
                rule = getattr(obs, "rule_name", "UnknownRule")
                target = getattr(obs, "target_identifier", target_id)
                dedup_key = ("YARA_RULE_MATCH", f"{rule}-{target}")
                if dedup_key not in seen_targets:
                    seen_targets.add(dedup_key)
                    recs.append(MitigationRecommendation(
                        recommendation_id=f"REC-{rec_counter:03d}",
                        target_evidence_id=target_id,
                        finding_title=f"YARA Signature Match: {rule}",
                        priority=MitigationPriority.HIGH,
                        action_type=MitigationActionType.INVESTIGATIVE,
                        reason=f"YARA rule '{rule}' matched target '{target}'. Strings matched: {len(getattr(obs, 'matched_strings', ()))}.",
                        recommended_action=(
                            f"1. Review context of matched strings for rule '{rule}' in forensic analysis workbench. "
                            f"2. Extract matching artifact from '{target}' for hash generation and threat intel correlation. "
                            "3. Corroborate signature hit with endpoint behavioral telemetry (EDR/SIEM)."
                        ),
                        human_authorization_required=True,
                        prerequisites="YARA signature documentation and artifact extraction tools.",
                        limitations="Static signature matches indicate pattern presence; corroboration is required."
                    ))
                    rec_counter += 1

        # 5. Handle Capability Failures / Missing Symbols
        if dossier.capability_failures:
            dedup_key = ("CAPABILITY_FAILURE", "GLOBAL")
            if dedup_key not in seen_targets:
                seen_targets.add(dedup_key)
                recs.append(MitigationRecommendation(
                    recommendation_id=f"REC-{rec_counter:03d}",
                    target_evidence_id=dossier.investigation_id,
                    finding_title="Forensic Capability Incomplete or Missing Symbols",
                    priority=MitigationPriority.MEDIUM,
                    action_type=MitigationActionType.INVESTIGATIVE,
                    reason=(
                        "One or more required analysis capabilities failed or were unavailable (e.g. missing OS symbols). "
                        "The analysis verdict is UNKNOWN/PARTIAL and cannot guarantee a clean state."
                    ),
                    recommended_action=(
                        "1. Identify the exact Windows build and kernel version from image metadata. "
                        "2. Download matching OS symbols (PDBs) to local symbol cache out-of-band. "
                        "3. Re-run memory forensics under Compy's strict offline policy."
                    ),
                    human_authorization_required=False,
                    prerequisites="Exact OS build metadata and offline symbol repository.",
                    limitations="Forensic plugins cannot verify kernel integrity without accurate symbol resolution."
                ))
                rec_counter += 1

        # Priority ordering: CRITICAL -> HIGH -> MEDIUM -> LOW
        priority_weights = {
            MitigationPriority.CRITICAL: 0,
            MitigationPriority.HIGH: 1,
            MitigationPriority.MEDIUM: 2,
            MitigationPriority.LOW: 3
        }
        recs.sort(key=lambda r: priority_weights.get(r.priority, 99))
        return recs
