/*
    Enhanced YARA ruleset for detecting PDF malware
    Author: Prashant Suthar
    Version: 2.0
    Description: This ruleset targets advanced PDF malware techniques, including JavaScript exploits, embedded objects, obfuscation, exploit kits, and phishing.
    License: GNU-GPLv2
*/

rule PDF_Magic_Header {
    meta:
        description = "Detects PDF magic header"
        weight = 1
    strings:
        $magic = { 25 50 44 46 } // %PDF
    condition:
        $magic at 0
}

rule Suspicious_JavaScript {
    meta:
        description = "Detects suspicious JavaScript in PDFs"
        weight = 4
    strings:
        $js_keyword = "/JavaScript"
        $eval = "eval("
        $unescape = "unescape("
        $fromCharCode = "String.fromCharCode"
        $shellcode = "%u9090%u9090" // NOP sled
        $js_obfuscation = /\/JS\(\d+\)/
    condition:
        $js_keyword and (any of ($eval, $unescape, $fromCharCode, $shellcode, $js_obfuscation))
}

rule Embedded_Executable {
    meta:
        description = "Detects embedded executables in PDFs"
        weight = 8
    strings:
        $exe_magic = { 4D 5A }  // MZ header for Windows executables
        $launch_action = "/Launch"
        $embedded_file = "/EmbeddedFile"
        $objstm = "/ObjStm"
        $stream_exe = /stream[\r\n]+.{0,100}MZ/  // MZ header inside an embedded stream
    condition:
        ($exe_magic and $stream_exe) and any of ($launch_action, $embedded_file, $objstm)
}


rule Obfuscation_Techniques {
    meta:
        description = "Detects common obfuscation techniques in PDFs"
        weight = 3
    strings:
        $flate_decode = "/FlateDecode"
        $ascii85_decode = "/ASCII85Decode"
        $hex_decode = "/ASCIIHexDecode"
        $lzw_decode = "/LZWDecode"
        $jbig2_decode = "/JBIG2Decode"
    condition:
        2 of ($flate_decode, $ascii85_decode, $hex_decode, $lzw_decode, $jbig2_decode)
}

rule Exploit_Kit_BlackHole {
    meta:
        description = "Detects BlackHole exploit kit patterns"
        weight = 4
    strings:
        $blackhole_pattern = "Index[5 1 7 1 9 4 23 4 50]"
        $blackhole_js = /var\s+\w+\s*=\s*new\s+Array\(\d+,\d+,\d+\)/
    condition:
        any of ($blackhole_pattern, $blackhole_js)
}

rule Exploit_Kit_Rig {
    meta:
        description = "Detects Rig exploit kit patterns"
        weight = 4
    strings:
        $rig_pattern1 = "RigEK" nocase
        $rig_pattern2 = "CVE-2018-8174" // Example CVE targeted by Rig
        $rig_js = /var\s+\w+\s*=\s*unescape\(\s*".+"\s*\)/
    condition:
        any of ($rig_pattern1, $rig_pattern2, $rig_js)
}

rule Shellcode_in_Metadata {
    meta:
        description = "Detects large Base64-encoded shellcode in metadata fields"
        weight = 5
    strings:
        $metadata_keywords = /\/Keywords.?\(([a-zA-Z0-9+\/=]{200,})\)/
        $metadata_author = /\/Author.?\(([a-zA-Z0-9+\/=]{200,})\)/
        $metadata_title = /\/Title.?\(([a-zA-Z0-9+\/=]{200,})\)/
    condition:
        any of ($metadata_keywords, $metadata_author, $metadata_title)
}



rule Invalid_Trailer_Structure {
    meta:
        description = "Detects manipulated or malformed PDF trailer sections"
        weight = 6
    strings:
        $trailer = "trailer"
        $xref = "xref"
        $startxref = "startxref"
        $eof = "%%EOF"
        $invalid_xref = /xref\s+[^\d\s]/  // Invalid cross-reference table format
        $manipulated_trailer = /trailer\s*<<\s*[^>]*Size\s+\d{6,}/  // Unusual Size value
    condition:
        $trailer and $xref and $startxref and $eof and any of ($invalid_xref, $manipulated_trailer)
}



rule Multiple_Versions {
    meta:
        description = "Detects multiple PDF versions in a single file"
        weight = 2
    strings:
        $version1 = /%PDF-1\.[0-9]/
        $version2 = /%PDF-2\.[0-9]/
    condition:
        #version1 > 1 or #version2 > 1
}

rule Suspicious_CreationDate {
    meta:
        description = "Detects suspicious CreationDate values"
        weight = 3
    strings:
        $creation_date = /CreationDate \(D:\d{14}\)/
        $invalid_date = /CreationDate \(00000000000000\)/
    condition:
        $creation_date or $invalid_date
}

rule XDP_Embedded_PDF {
    meta:
        description = "Detects XDP-embedded PDFs"
        weight = 3
    strings:
        $xdp_header = "<pdf xmlns="
        $xdp_chunk = "<chunk>"
    condition:
        $xdp_header and $xdp_chunk
}

rule Suspicious_Launch_Action {
    meta:
        description = "Detects suspicious launch actions"
        weight = 4
    strings:
        $launch = "/Launch"
        $action = "/Action"
        $url = "/URL"
    condition:
        $launch and (any of ($action, $url))
}

rule Suspicious_Embedded_Flash {
    meta:
        description = "Detects embedded Flash objects"
        weight = 3
    strings:
        $flash_magic = { 46 57 53 } // FWS (Flash file)
    condition:
        $flash_magic
}

rule Suspicious_Embedded_PDF {
    meta:
        description = "Detects embedded PDFs within other PDFs"
        weight = 3
    strings:
        $pdf_magic = { 25 50 44 46 }
    condition:
        #pdf_magic > 1
}

rule Suspicious_JBIG2 {
    meta:
        description = "Detects suspicious JBIG2Decode usage"
        weight = 3
    strings:
        $jbig2 = "/JBIG2Decode"
    condition:
        $jbig2
}


rule Suspicious_Embedded_JavaScript {
    meta:
        description = "Detects embedded JavaScript in suspicious contexts"
        weight = 4
    strings:
        $js = "/JavaScript"
        $open_action = "/OpenAction"
    condition:
        $js and $open_action
}

rule Suspicious_Embedded_Executable {
    meta:
        description = "Detects embedded executables in suspicious contexts"
        weight = 5
    strings:
        $exe_magic = { 4D 5A } // MZ header
        $launch = "/Launch"
    condition:
        $exe_magic and $launch
}

rule Suspicious_Embedded_URL {
    meta:
        description = "Detects embedded URLs in suspicious contexts"
        weight = 3
    strings:
        $url = "/URL"
        $action = "/Action"
    condition:
        $url and $action
}

rule Suspicious_Embedded_Executable_Action {
    meta:
        description = "Detects embedded executables with launch actions"
        weight = 5
    strings:
        $exe_magic = { 4D 5A } // MZ header
        $launch = "/Launch"
    condition:
        $exe_magic and $launch
}

rule Suspicious_Embedded_URL_Action {
    meta:
        description = "Detects embedded URLs with launch actions"
        weight = 3
    strings:
        $url = "/URL"
        $launch = "/Launch"
    condition:
        $url and $launch
}

rule Suspicious_Embedded_Flash_Action {
    meta:
        description = "Detects embedded Flash objects with launch actions"
        weight = 4
    strings:
        $flash_magic = { 46 57 53 } // FWS (Flash file)
        $launch = "/Launch"
    condition:
        $flash_magic and $launch
}

rule Suspicious_Embedded_PDF_Action {
    meta:
        description = "Detects embedded PDFs with launch actions"
        weight = 4
    strings:
        $pdf_magic = { 25 50 44 46 }
        $launch = "/Launch"
    condition:
        $pdf_magic and $launch
}

rule Suspicious_Embedded_JavaScript_Action {
    meta:
        description = "Detects embedded JavaScript with launch actions"
        weight = 4
    strings:
        $js = "/JavaScript"
        $launch = "/Launch"
    condition:
        $js and $launch
}