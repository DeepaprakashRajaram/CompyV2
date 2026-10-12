/*
   Compy Forensic YARA Rule Set: Ransomware Artifact Indicators
   Licensed under Apache 2.0.
   Purpose: Detects ransomware binary signatures, ransom note markers, and staging components.
*/

rule WannaCry_Execution_Artifacts {
    meta:
        description = "Detects WannaCry ransomware execution components, decrypters, and Tor proxy artifacts"
        author = "Compy Forensics"
        severity = "CRITICAL"
        mitre_technique = "T1486"
        category = "RANSOMWARE"
    strings:
        $s1 = "@WanaDecryptor@.exe" nocase ascii wide
        $s2 = "taskhsvc.exe" nocase ascii wide
        $s3 = "taskse.exe" nocase ascii wide
        $s4 = "TaskData\\Tor" nocase ascii wide
        $s5 = "WanaCrypt0r" nocase ascii wide
        $s6 = "wnry" nocase ascii wide
        $s7 = "c.wnry" nocase ascii wide
        $s8 = "t.wnry" nocase ascii wide
    condition:
        any of them
}

rule Ransomware_Decryption_Notice_Strings {
    meta:
        description = "Detects generic and WannaCry ransom note extortion notices"
        author = "Compy Forensics"
        severity = "CRITICAL"
        mitre_technique = "T1486"
        category = "RANSOMWARE"
    strings:
        $r1 = "Wana Decrypt0r" nocase ascii wide
        $r2 = "Ooops, your files have been encrypted!" nocase ascii wide
        $r3 = "Your files are encrypted" nocase ascii wide
        $r4 = "Please send $" nocase ascii wide
    condition:
        any of them
}
