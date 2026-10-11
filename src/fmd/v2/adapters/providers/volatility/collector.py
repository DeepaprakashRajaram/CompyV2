import logging
from typing import Tuple, Any, List

import volatility3
from volatility3.framework import contexts, automagic
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, psscan
from volatility3.framework.interfaces import renderers
from volatility3.framework.exceptions import PluginRequirementException, SymbolError, SymbolSpaceError

from fmd.v2.domain.contracts import (
    ICollector,
    IProviderResult,
    ProviderResult,
    ProviderCapability,
    CapabilityStatus,
    ProviderId
)
from fmd.v2.domain.evidence.provenance import ProvenanceRecord
from fmd.v2.adapters.providers.volatility.dtos import ProcessDTO

logger = logging.getLogger(__name__)

class VolatilityCollector(ICollector):
    def __init__(self, memory_image_path: str, artifact_hash: str):
        self.memory_image_path = memory_image_path
        self.artifact_hash = artifact_hash

    def provider_id(self) -> ProviderId:
        return ProviderId("volatility3-v2.28.2")

    def extract_evidence(self) -> IProviderResult:
        # Provenance setup
        from datetime import datetime, timezone
        provenance = ProvenanceRecord(
            _provider_id=self.provider_id(),
            _artifact_identity=self.artifact_hash,
            _acquisition_mode="NATIVE_VOLATILITY3",
            acquisition_time=datetime.now(timezone.utc)
        )
        
        ctx = contexts.Context()
        base_config_path = "automagic.LayerStacker.StackerLayer"
        ctx.config[f"{base_config_path}.location"] = f"file://{self.memory_image_path}"
        
        extracted_dtos: List[Any] = []
        capabilities = set()
        failures = []
        status = CapabilityStatus.SUCCESS
        
        try:
            # Enforce LOCAL_ONLY and FAIL_IF_MISSING safety boundaries
            from volatility3.framework import constants
            constants.OFFLINE = True
            
            from volatility3.framework.symbols.windows import pdbutil
            # Neutralize PDB downloading by monkeypatching the class method
            pdbutil.PDBUtility.download_pdb_isf = classmethod(lambda cls, *args, **kwargs: None)

            # 1. PsList execution (Active Process Linked List)
            plugin_pslist = pslist.PsList(ctx, config_path="plugins.windows.pslist.PsList")
            
            # Find and execute automagics
            available_automagics = automagic.available(ctx)
            chosen_automagics = automagic.choose_automagic(available_automagics, plugin_pslist)
            if chosen_automagics:
                for automagic_impl in chosen_automagics:
                    if automagic_impl.__class__.__name__ == "SymbolFinder":
                        pass
                    automagic_impl(ctx, plugin_pslist.config_path, plugin_pslist.build_configuration())
            
            treegrid = plugin_pslist.run()
            active_pids = set()
            
            for row in treegrid.populate():
                try:
                    pid = row.values[0]
                    ppid = row.values[1]
                    image_file_name = str(row.values[2])
                    offset = row.values[3]
                    threads = row.values[4]
                    handles = row.values[5]
                    create_time = row.values[8] if len(row.values) > 8 else None
                    exit_time = row.values[9] if len(row.values) > 9 else None
                    
                    int_pid = int(pid) if pid is not None else -1
                    if int_pid != -1:
                        active_pids.add(int_pid)

                    dto = ProcessDTO(
                        pid=int_pid,
                        ppid=int(ppid) if ppid is not None else -1,
                        image_file_name=image_file_name,
                        offset=int(offset) if offset is not None else 0,
                        threads=int(threads) if threads is not None else 0,
                        handles=int(handles) if handles is not None else 0,
                        create_time=create_time,
                        exit_time=exit_time,
                        is_hidden=False
                    )
                    extracted_dtos.append(dto)
                except Exception as row_e:
                    logger.warning(f"Failed to map pslist row: {row_e}")
                    
            capabilities.add(ProviderCapability.PROCESS_LIST)

            # 2. PsScan execution (Physical Memory Pool Carving for DKOM Rootkits)
            try:
                plugin_psscan = psscan.PsScan(ctx, config_path="plugins.windows.psscan.PsScan")
                treegrid_scan = plugin_psscan.run()
                for row in treegrid_scan.populate():
                    try:
                        pid = row.values[0]
                        ppid = row.values[1]
                        image_file_name = str(row.values[2])
                        offset = row.values[3]
                        threads = row.values[4]
                        handles = row.values[5]
                        create_time = row.values[8] if len(row.values) > 8 else None
                        exit_time = row.values[9] if len(row.values) > 9 else None
                        
                        int_pid = int(pid) if pid is not None else -1
                        # Flag as hidden if active (no exit time) but absent from active pslist
                        if int_pid != -1 and int_pid not in active_pids and exit_time is None:
                            dto = ProcessDTO(
                                pid=int_pid,
                                ppid=int(ppid) if ppid is not None else -1,
                                image_file_name=image_file_name,
                                offset=int(offset) if offset is not None else 0,
                                threads=int(threads) if threads is not None else 0,
                                handles=int(handles) if handles is not None else 0,
                                create_time=create_time,
                                exit_time=exit_time,
                                is_hidden=True
                            )
                            extracted_dtos.append(dto)
                    except Exception as scan_e:
                        logger.warning(f"Failed to map psscan row: {scan_e}")
                capabilities.add(ProviderCapability.PROCESS_SCAN)
            except Exception as psscan_e:
                logger.warning(f"PsScan execution skipped or failed: {psscan_e}")
            
        except (PluginRequirementException, SymbolError, SymbolSpaceError) as e:
            failures.append(f"Missing Symbol or Requirement: {str(e)}")
            status = CapabilityStatus.UNAVAILABLE
        except Exception as e:
            failures.append(f"Volatility failure: {str(e)}")
            status = CapabilityStatus.FAILED
            
        return ProviderResult(
            _capability_status=status,
            _available_capabilities=frozenset(capabilities),
            _extracted_dtos=(tuple(extracted_dtos), tuple()),
            _capability_failures=tuple(failures),
            _provenance=provenance
        )
