/*
   Compy Forensic YARA Rule Set: Fileless Download Cradles
   Licensed under Apache 2.0.
   Purpose: Detects in-memory script execution and download cradles in process command lines / buffers.
*/

rule PowerShell_Memory_Download_Cradle {
    meta:
        description = "Detects in-memory web download cradles used to fetch and execute payloads"
        author = "Compy Forensics"
        severity = "HIGH"
        mitre_technique = "T1059.001"
        category = "DOWNLOAD_CRADLE"
    strings:
        $s1 = "DownloadString" nocase ascii wide
        $s2 = "DownloadFile" nocase ascii wide
        $s3 = "DownloadData" nocase ascii wide
        $s4 = "Net.WebClient" nocase ascii wide
        $s5 = "Invoke-Expression" nocase ascii wide
        $s6 = "IEX" nocase ascii wide
        $s7 = "Net.HttpWebRequest" nocase ascii wide
    condition:
        ($s4 or $s7) and ($s1 or $s2 or $s3) and ($s5 or $s6)
}

rule Suspicious_Memory_Encoded_Command {
    meta:
        description = "Detects base64 encoded PowerShell execution indicators"
        author = "Compy Forensics"
        severity = "MEDIUM"
        mitre_technique = "T1027"
        category = "OBFUSCATION"
    strings:
        $enc1 = "-EncodedCommand" nocase ascii wide
        $enc2 = "-enc " nocase ascii wide
        $enc3 = "FromBase64String" nocase ascii wide
    condition:
        any of them
}
