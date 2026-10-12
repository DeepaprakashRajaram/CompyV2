"""
WHAT: Volatility 3 Forensic Collector Adapter.
WHY: Integrates native Volatility 3 framework for offline memory analysis.
OWNS: Invocation of Volatility 3 plugins, safe symbol handling, DTO mapping.
DOES NOT OWN: Reasoning, detection heuristics, report generation.
"""

import sys
import logging
from pathlib import Path
from typing import Tuple, Any, List, Dict, Optional

# Attempt to locate local workspace venv site-packages if volatility3 is not globally installed
try:
    import volatility3
except ImportError:
    for candidate in [
        Path(__file__).resolve().parents[7] / "fileless_detector" / "venv" / "Lib" / "site-packages",
        Path(__file__).resolve().parents[6] / "fileless_detector" / "venv" / "Lib" / "site-packages",
        Path(__file__).resolve().parents[5] / "venv" / "Lib" / "site-packages",
        Path(r"C:\Users\Deepak\Projects\FilelessMalwareDetector\fileless_detector\venv\Lib\site-packages"),
    ]:
        if candidate.exists() and str(candidate) not in sys.path:
            sys.path.append(str(candidate))
            try:
                import volatility3
                break
            except ImportError:
                pass

try:
    import volatility3
    from volatility3.framework import contexts, automagic, constants, plugins
    from volatility3.framework.configuration import requirements
    from volatility3.plugins.windows import pslist, psscan, cmdline
    try:
        from volatility3.plugins.windows.malware import malfind
    except ImportError:
        from volatility3.plugins.windows import malfind
    from volatility3.framework.interfaces import renderers
    from volatility3.framework.exceptions import PluginRequirementException, SymbolError, SymbolSpaceError
    from volatility3.framework.symbols.windows import pdbutil
    VOLATILITY_AVAILABLE = True
except ImportError:
    VOLATILITY_AVAILABLE = False
    PluginRequirementException = Exception
    SymbolError = Exception
    SymbolSpaceError = Exception

from fmd.v2.domain.contracts import (
    ICollector,
    IProviderResult,
    ProviderResult,
    ProviderCapability,
    CapabilityStatus,
    ProviderId
)
from fmd.v2.domain.evidence.provenance import ProvenanceRecord
from fmd.v2.adapters.providers.volatility.dtos import ProcessDTO, InjectedCodeDTO

logger = logging.getLogger(__name__)

class VolatilityCollector(ICollector):
    """
    Forensic collector executing Volatility 3 plugins against a local memory image.
    Enforces LOCAL_ONLY offline execution: never silently accesses the network
    or downloads symbols during analysis.
    """
    def __init__(self, memory_image_path: str, artifact_hash: str, yara_rules_dir: Optional[str] = None, enable_yara: bool = True):
        self.memory_image_path = memory_image_path
        self.artifact_hash = artifact_hash
        self.yara_rules_dir = yara_rules_dir or "rules/yara"
        self.enable_yara = enable_yara

    def provider_id(self) -> ProviderId:
        return ProviderId("volatility3-v2.28.2")

    @staticmethod
    def enforce_offline_symbol_policy():
        """Enforces LOCAL_ONLY offline execution without network symbol downloads."""
        if VOLATILITY_AVAILABLE:
            try:
                constants.OFFLINE = True
                pdbutil.PDBUtility.download_pdb_isf = classmethod(lambda cls, *args, **kwargs: None)
            except Exception as patch_e:
                logger.warning(f"Failed to enforce offline patch: {patch_e}")

    def extract_evidence(self) -> IProviderResult:
        from datetime import datetime, timezone
        provenance = ProvenanceRecord(
            _provider_id=self.provider_id(),
            _artifact_identity=self.artifact_hash,
            _acquisition_mode="NATIVE_VOLATILITY3",
            acquisition_time=datetime.now(timezone.utc)
        )
        
        if not VOLATILITY_AVAILABLE:
            return ProviderResult(
                _capability_status=CapabilityStatus.UNAVAILABLE,
                _available_capabilities=frozenset(),
                _extracted_dtos=(tuple(), tuple(), tuple()),
                _capability_failures=("Forensic provider 'volatility3' is not installed in runtime environment.",),
                _provenance=provenance
            )

        # Enforce LOCAL_ONLY and offline symbol policy
        self.enforce_offline_symbol_policy()

        image_path_obj = Path(self.memory_image_path).resolve()
        if not image_path_obj.exists():
            return ProviderResult(
                _capability_status=CapabilityStatus.FAILED,
                _available_capabilities=frozenset(),
                _extracted_dtos=(tuple(), tuple(), tuple()),
                _capability_failures=(f"Memory image file not found: {self.memory_image_path}",),
                _provenance=provenance
            )

        ctx = contexts.Context()
        base_config_path = "plugins"
        try:
            uri_location = image_path_obj.as_uri()
        except Exception:
            uri_location = f"file:///{str(image_path_obj).replace('\\', '/')}"
            
        ctx.config["automagic.LayerStacker.single_location"] = uri_location
        ctx.config["automagic.LayerStacker.StackerLayer.location"] = uri_location
        
        extracted_procs: List[ProcessDTO] = []
        extracted_injections: List[InjectedCodeDTO] = []
        capabilities = set()
        failures = []
        status = CapabilityStatus.SUCCESS
        
        try:
            automagics = automagic.available(ctx)

            def _is_unreadable(val) -> bool:
                if val is None:
                    return True
                return "Unreadable" in getattr(val.__class__, "__name__", "")

            def run_vol_plugin(plugin_class):
                constructed = plugins.construct_plugin(
                    context=ctx,
                    automagics=automagics,
                    plugin=plugin_class,
                    base_config_path=base_config_path,
                    progress_callback=None,
                    open_method=None
                )
                treegrid = constructed.run()
                rows = []
                def visitor(node, acc):
                    acc.append(node.values)
                    return acc
                treegrid.populate(visitor, rows)
                return rows

            # 1. PsList execution (Active Process Linked List)
            try:
                ps_rows = run_vol_plugin(pslist.PsList)
                active_pids = set()
                for row in ps_rows:
                    try:
                        pid = row[0]
                        ppid = row[1]
                        raw_name = row[2]
                        image_file_name = str(raw_name) if raw_name and not _is_unreadable(raw_name) else "Unknown"
                        offset = row[3] if len(row) > 3 and not _is_unreadable(row[3]) else 0
                        threads = row[4] if len(row) > 4 and not _is_unreadable(row[4]) else 0
                        handles = row[5] if len(row) > 5 and not _is_unreadable(row[5]) else 0
                        create_time = row[8] if len(row) > 8 and not _is_unreadable(row[8]) else None
                        exit_time = row[9] if len(row) > 9 and not _is_unreadable(row[9]) else None
                        
                        int_pid = int(pid) if pid is not None and not _is_unreadable(pid) else -1
                        if int_pid != -1:
                            active_pids.add(int_pid)

                        dto = ProcessDTO(
                            pid=int_pid,
                            ppid=int(ppid) if ppid is not None and not _is_unreadable(ppid) else -1,
                            image_file_name=image_file_name,
                            offset=int(offset) if offset is not None else 0,
                            threads=int(threads) if threads is not None else 0,
                            handles=int(handles) if handles is not None else 0,
                            create_time=create_time,
                            exit_time=exit_time,
                            source_view="PSLIST",
                            is_hidden=False
                        )
                        extracted_procs.append(dto)
                    except Exception as row_e:
                        logger.warning(f"Failed to map pslist row: {row_e}")
                capabilities.add(ProviderCapability.PROCESS_LIST)
            except Exception as ps_e:
                logger.warning(f"PsList execution failed: {ps_e}")
                failures.append(f"PsList failed: {ps_e}")

            # 2. CmdLine execution (Extract command line arguments for active processes)
            try:
                cmd_rows = run_vol_plugin(cmdline.CmdLine)
                cmdline_map: Dict[int, str] = {}
                for row in cmd_rows:
                    try:
                        c_pid = int(row[0]) if row[0] is not None and not _is_unreadable(row[0]) else -1
                        raw_args = row[2] if len(row) > 2 else ""
                        if _is_unreadable(raw_args) or raw_args is None:
                            c_args = ""
                        else:
                            c_args = str(raw_args).strip()
                        if c_pid != -1 and c_args:
                            cmdline_map[c_pid] = c_args
                    except Exception:
                        pass
                
                # Enrich extracted_procs with cmdline
                if cmdline_map:
                    updated_procs = []
                    for p in extracted_procs:
                        if p.pid in cmdline_map:
                            updated_procs.append(ProcessDTO(
                                pid=p.pid,
                                ppid=p.ppid,
                                image_file_name=p.image_file_name,
                                offset=p.offset,
                                create_time=p.create_time,
                                exit_time=p.exit_time,
                                threads=p.threads,
                                handles=p.handles,
                                source_view=p.source_view,
                                is_hidden=p.is_hidden,
                                cmdline=cmdline_map[p.pid]
                            ))
                        else:
                            updated_procs.append(p)
                    extracted_procs = updated_procs
                capabilities.add(ProviderCapability.COMMAND_LINE)
            except Exception as cmd_e:
                logger.info(f"CmdLine plugin skipped or unsupported on this image: {cmd_e}")

            # 3. PsScan execution (Physical Memory Pool Carving for process structures)
            try:
                scan_rows = run_vol_plugin(psscan.PsScan)
                for row in scan_rows:
                    try:
                        pid = row[0]
                        ppid = row[1]
                        raw_name = row[2]
                        image_file_name = str(raw_name) if raw_name and not _is_unreadable(raw_name) else "Unknown"
                        offset = row[3] if len(row) > 3 and not _is_unreadable(row[3]) else 0
                        threads = row[4] if len(row) > 4 and not _is_unreadable(row[4]) else 0
                        handles = row[5] if len(row) > 5 and not _is_unreadable(row[5]) else 0
                        create_time = row[8] if len(row) > 8 and not _is_unreadable(row[8]) else None
                        exit_time = row[9] if len(row) > 9 and not _is_unreadable(row[9]) else None
                        
                        int_pid = int(pid) if pid is not None and not _is_unreadable(pid) else -1
                        dto = ProcessDTO(
                            pid=int_pid,
                            ppid=int(ppid) if ppid is not None and not _is_unreadable(ppid) else -1,
                            image_file_name=image_file_name,
                            offset=int(offset) if offset is not None else 0,
                            threads=int(threads) if threads is not None else 0,
                            handles=int(handles) if handles is not None else 0,
                            create_time=create_time,
                            exit_time=exit_time,
                            source_view="PSSCAN",
                            is_hidden=False
                        )
                        extracted_procs.append(dto)
                    except Exception as scan_e:
                        logger.warning(f"Failed to map psscan row: {scan_e}")
                capabilities.add(ProviderCapability.PROCESS_SCAN)
            except Exception as psscan_e:
                logger.warning(f"PsScan execution skipped or failed: {psscan_e}")

            # 4. Malfind execution (Suspicious injected or unbacked executable memory)
            try:
                mal_rows = run_vol_plugin(malfind.Malfind)
                for row in mal_rows:
                    try:
                        m_pid = int(row[0]) if row[0] is not None and not _is_unreadable(row[0]) else 0
                        raw_proc = row[1] if len(row) > 1 else ""
                        m_proc = str(raw_proc) if raw_proc and not _is_unreadable(raw_proc) else ""
                        m_start = int(row[2]) if len(row) > 2 and row[2] and not _is_unreadable(row[2]) else 0
                        m_end = int(row[3]) if len(row) > 3 and row[3] and not _is_unreadable(row[3]) else 0
                        raw_tag = row[4] if len(row) > 4 else ""
                        m_tag = str(raw_tag) if raw_tag and not _is_unreadable(raw_tag) else ""
                        raw_prot = row[5] if len(row) > 5 else ""
                        m_prot = str(raw_prot) if raw_prot and not _is_unreadable(raw_prot) else ""
                        m_commit = int(row[6]) if len(row) > 6 and row[6] and not _is_unreadable(row[6]) else 0
                        raw_hexdump = row[10] if len(row) > 10 else ""
                        m_hexdump = str(raw_hexdump) if raw_hexdump and not _is_unreadable(raw_hexdump) else ""
                        raw_disasm = row[11] if len(row) > 11 else ""
                        m_disasm = str(raw_disasm) if raw_disasm and not _is_unreadable(raw_disasm) else ""
                        
                        inj_dto = InjectedCodeDTO(
                            pid=m_pid,
                            process_name=m_proc,
                            start_vpn=m_start,
                            end_vpn=m_end,
                            tag=m_tag,
                            protection=m_prot,
                            commit_charge=m_commit,
                            hexdump_preview=m_hexdump,
                            disasm_preview=m_disasm
                        )
                        extracted_injections.append(inj_dto)
                    except Exception as mal_row_e:
                        logger.warning(f"Failed to map malfind row: {mal_row_e}")
                capabilities.add(ProviderCapability.INJECTED_CODE)
            except Exception as malfind_e:
                logger.info(f"Malfind plugin skipped or unsupported on this image: {malfind_e}")

            # 5. Execute YARA Signature Scanning Pipeline
            extracted_yara_matches = []
            if self.enable_yara:
                try:
                    from fmd.v2.adapters.providers.yara.scanner import YaraScannerProvider
                    yara_scanner = YaraScannerProvider(rules_dir=self.yara_rules_dir)
                    if yara_scanner.status == CapabilityStatus.SUCCESS:
                        capabilities.add(ProviderCapability.YARA_SCAN)
                        for inj in extracted_injections:
                            m_list = yara_scanner.scan_injected_artifact(
                                pid=inj.pid,
                                process_name=inj.process_name,
                                start_addr=inj.start_vpn,
                                hexdump_preview=inj.hexdump_preview,
                                disasm_preview=inj.disasm_preview
                            )
                            extracted_yara_matches.extend(m_list)
                        for p in extracted_procs:
                            if getattr(p, "cmdline", None):
                                m_list = yara_scanner.scan_cmdline(
                                    pid=p.pid,
                                    process_name=p.image_file_name,
                                    cmdline=p.cmdline
                                )
                                extracted_yara_matches.extend(m_list)
                            if getattr(p, "image_file_name", None):
                                m_list = yara_scanner.scan_process_identity(
                                    pid=p.pid,
                                    process_name=p.image_file_name
                                )
                                extracted_yara_matches.extend(m_list)
                        
                        # Deduplicate matches by (rule_name, target_identifier, matched_strings)
                        seen_m = set()
                        deduped_matches = []
                        for m in extracted_yara_matches:
                            m_key = (m.rule_name, m.target_identifier, m.matched_strings)
                            if m_key not in seen_m:
                                seen_m.add(m_key)
                                deduped_matches.append(m)
                        extracted_yara_matches = deduped_matches
                    elif yara_scanner.status == CapabilityStatus.FAILED:
                        failures.append(f"YARA Error: {yara_scanner.failure_reason}")
                    elif yara_scanner.status == CapabilityStatus.UNAVAILABLE:
                        failures.append(f"YARA Scanner Unavailable: {yara_scanner.failure_reason or 'Engine unavailable'}")
                except Exception as yara_e:
                    failures.append(f"YARA scan execution failure: {yara_e}")
            
        except (PluginRequirementException, SymbolError, SymbolSpaceError) as e:
            failures.append(
                f"Missing Symbol or Requirement: {str(e)}. "
                "Local-only offline symbol policy enforced; missing symbols are reported honestly."
            )
            status = CapabilityStatus.UNAVAILABLE
        except Exception as e:
            failures.append(f"Volatility failure: {str(e)}")
            status = CapabilityStatus.FAILED

        if len(capabilities) > 0 and len(failures) > 0:
            status = CapabilityStatus.PARTIAL
            
        return ProviderResult(
            _capability_status=status,
            _available_capabilities=frozenset(capabilities),
            _extracted_dtos=(
                tuple(extracted_procs), 
                tuple(), 
                tuple(extracted_injections),
                tuple(extracted_yara_matches if 'extracted_yara_matches' in locals() else ())
            ),
            _capability_failures=tuple(failures),
            _provenance=provenance
        )
