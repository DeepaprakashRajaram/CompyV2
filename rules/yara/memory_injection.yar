/*
   Compy Forensic YARA Rule Set: In-Memory Injected Code Indicators
   Licensed under Apache 2.0.
   Purpose: Detects unbacked PE headers and common shellcode prologues in memory artifacts.
*/

rule Windows_PE_Header_In_Memory {
    meta:
        description = "Detects unbacked or injected executable PE header in memory allocation"
        author = "Compy Forensics"
        severity = "HIGH"
        mitre_technique = "T1055"
        category = "CODE_INJECTION"
    strings:
        $mz_dos = { 4D 5A 90 00 }
        $pe_sig = { 50 45 00 00 }
        $this_program = "This program cannot be run in DOS mode" ascii
    condition:
        $mz_dos at 0 or ($mz_dos and $this_program) or ($mz_dos and $pe_sig)
}

rule Shellcode_Common_Prologues {
    meta:
        description = "Detects common shellcode execution prologues and API hashing stubs"
        author = "Compy Forensics"
        severity = "HIGH"
        mitre_technique = "T1055.002"
        category = "SHELLCODE"
    strings:
        // cld; call $+5; pop reg (common egg hunter / relative address resolution)
        $cld_call = { FC E8 00 00 00 00 }
        // x64 function prologue with stack adjustment
        $x64_prologue = { 48 83 EC 28 }
        // VirtualAlloc / GetProcAddress hash lookup stub
        $api_hash_stub = { 64 A1 30 00 00 00 } // FS:[0x30] PEB lookup x86
        $api_hash_stub_x64 = { 65 48 8B 04 25 60 00 00 00 } // GS:[0x60] PEB lookup x64
    condition:
        any of them
}
