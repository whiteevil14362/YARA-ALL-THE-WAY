rule Office_Macro_Malware {
    meta:
        description = "Detects malicious macros in Office files"
        weight = 5
    strings:
        $vba_auto_open = "Sub AutoOpen()" nocase
        $vba_document_open = "Sub Document_Open()" nocase
        $vba_shell = "Shell(" nocase
        $vba_exec = "Exec(" nocase
        $vba_obfuscation = /StrReverse\(|Chr\(|Asc\(/ nocase
    condition:
        any of ($vba_auto_open, $vba_document_open) and
        any of ($vba_shell, $vba_exec, $vba_obfuscation)
}

rule Office_Exploit_CVE_2017_0199 {
    meta:
        description = "Detects CVE-2017-0199 exploit in Office files"
        weight = 5
    strings:
        $ole_object = "oledata.mso"
        $hta_script = /<script.*>.*<\/script>/ nocase
    condition:
        $ole_object and $hta_script
}

rule Office_Embedded_Executable {
    meta:
        description = "Detects embedded executables in Office files"
        weight = 5
    strings:
        $exe_magic = { 4D 5A } // MZ header
        $ole_object = "oledata.mso"
    condition:
        $exe_magic and $ole_object
}

rule Office_Phishing_URLs {
    meta:
        description = "Detects phishing URLs in Office files"
        weight = 3
    strings:
        $url1 = "http://phishing.com" nocase
        $url2 = "https://malicious.site" nocase
        $url3 = /http:\/\/[a-zA-Z0-9]{1,}\.(com|net|org|info|xyz)/
        $url4 = /https:\/\/[a-zA-Z0-9]{1,}\.(com|net|org|info|xyz)/
    condition:
        any of ($url*)
}

rule Office_PowerShell_Malware {
    meta:
        description = "Detects PowerShell-based malware in Office files"
        weight = 5
    strings:
        $ps_command = "powershell" nocase
        $ps_invoke = "Invoke-Expression" nocase
        $ps_download = "DownloadString(" nocase
    condition:
        $ps_command and (any of ($ps_invoke, $ps_download))
}

rule Office_Social_Engineering {
    meta:
        description = "Detects social engineering text in Office files"
        weight = 3
    strings:
        $enable_macros = "Enable macros to view this document" nocase
        $click_here = "Click here to enable content" nocase
    condition:
        any of ($enable_macros, $click_here)
}

rule Office_Obfuscated_VBA {
    meta:
        description = "Detects obfuscated VBA code in Office files"
        weight = 4
    strings:
        $vba_obfuscation1 = /StrReverse\(/ nocase
        $vba_obfuscation2 = /Chr\(/ nocase
        $vba_obfuscation3 = /Asc\(/ nocase
    condition:
        2 of ($vba_obfuscation*)
}