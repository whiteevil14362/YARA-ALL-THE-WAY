import "pe"

rule AdvancedMalwareDetection_V12 {
   meta:
      description = "Advanced malware detection rule with reduced false positives"
      author = "Nikhil Analyst"
      version = "12.0"
      last_updated = "2023-10-01"
      reference = "https://example.com/threat-intel"
      severity = "High"

   strings:
      // Common malware strings
      $wannacry = "WannaCry" nocase wide ascii
      $emotet = "emotet" nocase wide ascii
      $trickbot = "trickbot" nocase wide ascii
      $ryuk = "Ryuk" nocase wide ascii
      $conti = "Conti" nocase wide ascii
      $revil = "REvil" nocase wide ascii

      // Suspicious APIs
      $valloc = "VirtualAlloc" nocase wide ascii
      $vprotect = "VirtualProtect" nocase wide ascii
      $cremthread = "CreateRemoteThread" nocase wide ascii
      $loadlibrary = "LoadLibrary" nocase wide ascii
      $getprocaddress = "GetProcAddress" nocase wide ascii

      // Obfuscated strings
      $b64_regex = /[A-Za-z0-9+\/=]{50,}/ nocase
      $hex_regex = /\\x[0-9A-F]{2,}/i
      $encrypted_regex = /(encrypt|decrypt|cipher)/ nocase

      // Network IoCs
      $http = "http://" nocase wide ascii
      $https = "https://" nocase wide ascii
      $mal_domains = /(pastebin\.com|transfer\.sh|malicious\.xyz|evil\.com|ransom\.xyz)/ nocase
      $mal_ips = /(192\.168\.1\.100|10\.0\.0\.1|172\.16\.0\.1)/
      $ip_regex = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

      // Behavioral indicators
      $persistence = /(HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)/ nocase
      $injection = /(WriteProcessMemory|NtCreateThreadEx)/ nocase
      $powershell = "powershell" nocase wide ascii

      // Known legitimate files (e.g., Notepad, Explorer, VSCode, Office, etc.)
      $notepad = "notepad.exe" nocase wide ascii
      $explorer = "explorer.exe" nocase wide ascii
      $chrome = "chrome.exe" nocase wide ascii
      $vscode = "vscode.exe" nocase wide ascii
      $vscode_installer = /VSCodeUserSetup.*\.exe/ nocase
      $winword = "winword.exe" nocase wide ascii
      $excel = "excel.exe" nocase wide ascii
      $powerpnt = "powerpnt.exe" nocase wide ascii
      $outlook = "outlook.exe" nocase wide ascii
      $vlc = "vlc.exe" nocase wide ascii
      $spotify = "spotify.exe" nocase wide ascii
      $msmpeng = "msmpeng.exe" nocase wide ascii
      $teams = "teams.exe" nocase wide ascii
      $steam = "steam.exe" nocase wide ascii
      $vmware = "vmware.exe" nocase wide ascii
      $acrobat = "acrobat.exe" nocase wide ascii
      $photoshop = "photoshop.exe" nocase wide ascii
      $winrar = "winrar.exe" nocase wide ascii
      $7zfm = "7zfm.exe" nocase wide ascii
      $utorrent = "utorrent.exe" nocase wide ascii

      // Additional legitimate files from the previous list
      $firefox = "firefox.exe" nocase wide ascii
      $msedge = "msedge.exe" nocase wide ascii
      $iexplore = "iexplore.exe" nocase wide ascii
      $opera = "opera.exe" nocase wide ascii
      $devenv = "devenv.exe" nocase wide ascii
      $pycharm = "pycharm.exe" nocase wide ascii
      $eclipse = "eclipse.exe" nocase wide ascii
      $notepadplus = "notepad++.exe" nocase wide ascii
      $javaw = "javaw.exe" nocase wide ascii
      $python = "python.exe" nocase wide ascii
      $node = "node.exe" nocase wide ascii
      $git = "git.exe" nocase wide ascii
      $tortoisegit = "tortoisegit.exe" nocase wide ascii
      $svn = "svn.exe" nocase wide ascii
      $onenote = "onenote.exe" nocase wide ascii
      $mso = "mso.dll" nocase wide ascii
      $vbe7 = "vbe7.dll" nocase wide ascii
      $wmplayer = "wmplayer.exe" nocase wide ascii
      $potplayer = "potplayer.exe" nocase wide ascii
      $itunes = "itunes.exe" nocase wide ascii
      $winamp = "winamp.exe" nocase wide ascii
      $avp = "avp.exe" nocase wide ascii
      $bdagent = "bdagent.exe" nocase wide ascii
      $mcshield = "mcshield.exe" nocase wide ascii
      $egui = "egui.exe" nocase wide ascii
      $onedrive = "onedrive.exe" nocase wide ascii
      $dropbox = "dropbox.exe" nocase wide ascii
      $googledrivesync = "googledrivesync.exe" nocase wide ascii
      $slack = "slack.exe" nocase wide ascii
      $zoom = "zoom.exe" nocase wide ascii
      $epicgameslauncher = "epicgameslauncher.exe" nocase wide ascii
      $origin = "origin.exe" nocase wide ascii
      $battlenet = "battle.net.exe" nocase wide ascii
      $minecraft = "minecraft.exe" nocase wide ascii
      $fortnite = "fortnite.exe" nocase wide ascii
      $csgo = "csgo.exe" nocase wide ascii
      $virtualbox = "virtualbox.exe" nocase wide ascii
      $vboxservice = "vboxservice.exe" nocase wide ascii
      $teamviewer = "teamviewer.exe" nocase wide ascii
      $anydesk = "anydesk.exe" nocase wide ascii
      $rdpclip = "rdpclip.exe" nocase wide ascii
      $foxitreader = "foxitreader.exe" nocase wide ascii
      $qbittorrent = "qbittorrent.exe" nocase wide ascii
      $illustrator = "illustrator.exe" nocase wide ascii
      $coreldraw = "coreldraw.exe" nocase wide ascii

   condition:
      // Ensure it's a valid PE file
      pe.is_pe and

      // Exclude known legitimate files
      not any of (
         $notepad, $explorer, $chrome, $vscode, $vscode_installer, $winword, $excel, $powerpnt, $outlook, $vlc, $spotify, $msmpeng, $teams, $steam, $vmware, $acrobat, $photoshop, $winrar, $7zfm, $utorrent,
         $firefox, $msedge, $iexplore, $opera, $devenv, $pycharm, $eclipse, $notepadplus, $javaw, $python, $node, $git, $tortoisegit, $svn, $onenote, $mso, $vbe7, $wmplayer, $potplayer, $itunes, $winamp,
         $avp, $bdagent, $mcshield, $egui, $onedrive, $dropbox, $googledrivesync, $slack, $zoom, $epicgameslauncher, $origin, $battlenet, $minecraft, $fortnite, $csgo, $virtualbox, $vboxservice, $teamviewer, $anydesk, $rdpclip, $foxitreader, $qbittorrent, $illustrator, $coreldraw
      ) and

      // High-confidence detection logic
      (
         // Malware family detection
         any of ($wannacry, $emotet, $trickbot, $ryuk, $conti, $revil) or

         // Suspicious API combinations
         ( all of ($valloc, $vprotect, $cremthread) and not $vscode and not $vscode_installer ) or

         // Obfuscation techniques
         ( any of ($b64_regex, $hex_regex, $encrypted_regex) and not $vscode and not $vscode_installer ) or

         // Network IoCs
         ( ($http or $https) and any of ($mal_domains, $mal_ips) ) or

         // Behavioral indicators
         ( any of ($persistence, $injection) and not $vscode and not $vscode_installer ) or

         // Heuristic: Multiple suspicious indicators
         ( 
            (2 of ($valloc, $vprotect, $cremthread, $loadlibrary, $getprocaddress)) and
            (1 of ($b64_regex, $hex_regex, $encrypted_regex))
         ) or

         // Detect IP addresses in strings
         $ip_regex or

         // Detect PowerShell usage
         $powershell
      )
}

rule XWorm {
    meta:
        author = "ditekSHen"
        description = "Detects XWorm"
        cape_type = "XWorm Payload"
    strings:
        $x1 = "XWorm " wide nocase
        $x2 = /XWorm\s(V|v)\d+\.\d+/ fullword wide
        $s1 = "RunBotKiller" fullword wide
        $s2 = "XKlog.txt" fullword wide
        $s3 = /(shell|reg)fuc/ fullword wide
        $s4 = "closeshell" fullword ascii
        $s5 = { 62 00 79 00 70 00 73 00 73 00 00 ?? 63 00 61 00 6c 00 6c 00 75 00 61 00 63 00 00 ?? 73 00 63 00 }
        $s6 = { 44 00 44 00 6f 00 73 00 54 00 00 ?? 43 00 69 00 6c 00 70 00 70 00 65 00 72 00 00 ?? 50 00 45 00 }
        $s7 = { 69 00 6e 00 6a 00 52 00 75 00 6e 00 00 ?? 73 00 74 00 61 00 72 00 74 00 75 00 73 00 62 }
        $s8 = { 48 6f 73 74 00 50 6f 72 74 00 75 70 6c 6f 61 64 65 72 00 6e 61 6d 65 65 65 00 4b 45 59 00 53 50 4c 00 4d 75 74 65 78 78 00 }
        $v2_1 = "PING!" fullword wide
        $v2_2 = "Urlhide" fullword wide
        $v2_3 = /PC(Restart|Shutdown)/ fullword wide
        $v2_4 = /(Start|Stop)(DDos|Report)/ fullword wide
        $v2_5 = /Offline(Get|Keylogger)/ wide
        $v2_6 = "injRun" fullword wide
        $v2_7 = "Xchat" fullword wide
        $v2_8 = "UACFunc" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and (3 of ($s*) or 3 of ($v2*))) or 6 of them)
}

rule xworm_kingrat {
    meta:
        author = "jeFF0Falltrades"
        cape_type = "XWorm payload"
    strings:
        $str_xworm = "xworm" wide ascii nocase
        $str_xwormmm = "Xwormmm" wide ascii
        $str_xclient = "XClient" wide ascii
        $str_default_log = "\\Log.tmp" wide ascii
        $str_create_proc = "/create /f /RL HIGHEST /sc minute /mo 1 /t" wide ascii
        $str_ddos_start = "StartDDos" wide ascii
        $str_ddos_stop = "StopDDos" wide ascii
        $str_timeout = "timeout 3 > NUL" wide ascii
        $byte_md5_hash = { 7e [3] 04 28 [3] 06 6f }
        $patt_config = { 72 [3] 70 80 [3] 04 }
    condition:
        5 of them and #patt_config >= 7
}

rule INDICATOR_SUSPICIOUS_Binary_References_Browsers {
    meta:
        description = "Detects binaries (Windows and macOS) referencing many web browsers. Observed in information stealers."
        author = "ditekSHen"
    strings:
        $s1 = "Uran\\User Data" nocase ascii wide
        $s2 = "Amigo\\User Data" nocase ascii wide
        $s3 = "Torch\\User Data" nocase ascii wide
        $s4 = "Chromium\\User Data" nocase ascii wide
        $s5 = "Nichrome\\User Data" nocase ascii wide
        $s6 = "Google\\Chrome\\User Data" nocase ascii wide
        $s7 = "360Browser\\Browser\\User Data" nocase ascii wide
        $s8 = "Maxthon3\\User Data" nocase ascii wide
        $s9 = "Comodo\\User Data" nocase ascii wide
        $s10 = "CocCoc\\Browser\\User Data" nocase ascii wide
        $s11 = "Vivaldi\\User Data" nocase ascii wide
        $s12 = "Opera Software\\" nocase ascii wide
        $s13 = "Kometa\\User Data" nocase ascii wide
        $s14 = "Comodo\\Dragon\\User Data" nocase ascii wide
        $s15 = "Sputnik\\User Data" nocase ascii wide
        $s16 = "Google (x86)\\Chrome\\User Data" nocase ascii wide
        $s17 = "Orbitum\\User Data" nocase ascii wide
        $s18 = "Yandex\\YandexBrowser\\User Data" nocase ascii wide
        $s19 = "K-Melon\\User Data" nocase ascii wide
        $s20 = "Flock\\Browser" nocase ascii wide
        $s21 = "ChromePlus\\User Data" nocase ascii wide
        $s22 = "UCBrowser\\" nocase ascii wide
        $s23 = "Mozilla\\SeaMonkey" nocase ascii wide
        $s24 = "Apple\\Apple Application Support\\plutil.exe" nocase ascii wide
        $s25 = "Preferences\\keychain.plist" nocase ascii wide
        $s26 = "SRWare Iron" ascii wide
        $s27 = "CoolNovo" ascii wide
        $s28 = "BlackHawk\\Profiles" ascii wide
        $s29 = "CocCoc\\Browser" ascii wide
        $s30 = "Cyberfox\\Profiles" ascii wide
        $s31 = "Epic Privacy Browser\\" ascii wide
        $s32 = "K-Meleon\\" ascii wide
        $s33 = "Maxthon5\\Users" ascii wide
        $s34 = "Nichrome\\User Data" ascii wide
        $s35 = "Pale Moon\\Profiles" ascii wide
        $s36 = "Waterfox\\Profiles" ascii wide
        $s37 = "Amigo\\User Data" ascii wide
        $s38 = "CentBrowser\\User Data" ascii wide
        $s39 = "Chedot\\User Data" ascii wide
        $s40 = "RockMelt\\User Data" ascii wide
        $s41 = "Go!\\User Data" ascii wide
        $s42 = "7Star\\User Data" ascii wide
        $s43 = "QIP Surf\\User Data" ascii wide
        $s44 = "Elements Browser\\User Data" ascii wide
        $s45 = "TorBro\\Profile" ascii wide
        $s46 = "Suhba\\User Data" ascii wide
        $s47 = "Secure Browser\\User Data" ascii wide
        $s48 = "Mustang\\User Data" ascii wide
        $s49 = "Superbird\\User Data" ascii wide
        $s50 = "Xpom\\User Data" ascii wide
        $s51 = "Bromium\\User Data" ascii wide
        $s52 = "Brave\\" nocase ascii wide
        $s53 = "Google\\Chrome SxS\\User Data" ascii wide
        $s54 = "Microsoft\\Internet Explorer" ascii wide
        $s55 = "Packages\\Microsoft.MicrosoftEdge_" ascii wide
        $s56 = "IceDragon\\Profiles" ascii wide
        $s57 = "\\AdLibs\\" nocase ascii wide
        $s58 = "Moonchild Production\\Pale Moon" nocase ascii wide
        $s59 = "Firefox\\Profiles" nocase ascii wide
        $s60 = "AVG\\Browser\\User Data" nocase ascii wide
        $s61 = "Kinza\\User Data" nocase ascii wide
        $s62 = "URBrowser\\User Data" nocase ascii wide
        $s63 = "AVAST Software\\Browser\\User Data" nocase ascii wide
        $s64 = "SalamWeb\\User Data" nocase ascii wide
        $s65 = "Slimjet\\User Data" nocase ascii wide
        $s66 = "Iridium\\User Data" nocase ascii wide
        $s67 = "Blisk\\User Data" nocase ascii wide
        $s68 = "uCozMedia\\Uran\\User Data" nocase ascii wide
        $s69 = "setting\\modules\\ChromiumViewer" nocase ascii wide
        $s70 = "Citrio\\User Data" nocase ascii wide
        $s71 = "Coowon\\User Data" nocase ascii wide
        $s72 = "liebao\\User Data" nocase ascii wide
        $s73 = "Edge\\User Data" nocase ascii wide
        $s74 = "BlackHawk\\User Data" nocase ascii wide
        $s75 = "QQBrowser\\User Data" nocase ascii wide
        $s76 = "GhostBrowser\\User Data" nocase ascii wide
        $s77 = "Xvast\\User Data" nocase ascii wide
        $s78 = "360Chrome\\Chrome\\User Data" nocase ascii wide
        $s79 = "Brave-Browser\\User Data" nocase ascii wide
        $s80 = "Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer" nocase ascii wide
        $s81 = "Chromodo\\User Data" nocase ascii wide
        $s82 = "Mail.Ru\\Atom\\User Data" nocase ascii wide
        $s83 = "8pecxstudios\\Cyberfox" nocase ascii wide
        $s84 = "NETGATE Technologies\\BlackHaw" nocase ascii wide
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0xfacf) and 6 of them
}

rule INDICATOR_SUSPICIOUS_EXE_Crypto_Wallet_Regex {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing cryptocurrency wallet regular expressions"
    strings:
        $s1 = "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$" ascii wide nocase // Bitcoin (BTC)
        $s2 = "(?:^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$)" ascii wide nocase // Litecoin (LTC)
        $s3 = "(?:^0x[a-fA-F0-9]{40}$)" ascii wide nocase // Ethereum (ETH)
        $s4 = "(?:^G[0-9a-zA-Z]{55}$)" ascii wide nocase // Stellar Lumens (XLM)
        $s5 = "^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$" ascii wide nocase // Monero (XMR)
        $s6 = "(^[1-9A-HJ-NP-Za-km-z]{44}$)" ascii wide nocase // Solana (SOL)
        $s7 = "T[A-Za-z1-9]{33}" ascii wide nocase // Tezos (XTZ)
        $s8 = "(?:^r[0-9a-zA-Z]{24,34}$)" ascii wide nocase // Ripple (XRP)
        $s9 = "^((bitcoincash:)?(q|p)[a-z0-9]{41})" ascii wide nocase // Bitcoin Cash (BCH)
        $s10 = "(?:^X[1-9A-HJ-NP-Za-km-z]{33}$)" ascii wide nocase //Dash (DASH)
        $s11 = "(?:^A[0-9a-zA-Z]{33}$)" ascii wide nocase // Ontology (ONT)
        $s12 = "D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}" ascii wide nocase // Dogecoin (DOGE)
        $s13 = "(^0x[A-Za-z0-9]{40,40}?[\\d\\- ])|(^0x[A-Za-z0-9]{40,40})$" ascii wide nocase
        $s14 = "(^D[A-Za-z0-9]{32,35}?[\\d\\- ])|(^D[A-Za-z0-9]{32,35})$" ascii wide nocase
        $s15 = "^([13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})$" ascii wide nocase
        $s16 = "(^X[A-Za-z0-9]{32,34}?[\\d\\- ])|(^X[A-Za-z0-9]{32,34})|(^7[A-Za-z0-9]{32,34})$" ascii wide nocase
        $s17 = "(^t[A-Za-z0-9]{32,36})$" ascii wide nocase
        $s18 = "(^(GD|GC)[A-Z0-9]{54,56})$" ascii wide nocase
    condition:
         (uint16(0) == 0x5a4d and 3 of them) or (5 of them)
}

rule INDICATOR_SUSPICIOUS_EXE_References_AdsBlocker_Browser_Extension_IDs {
    meta:
        author = "ditekSHen"
        description = "Detect executables referencing considerable number of Ads blocking browser extension IDs"
    strings:
        $s1 = "gighmmpiobklfepjocnamgkkbiglidom" ascii wide nocase // AdBlock
        $s2 = "cfhdojbkjhnklbpkdaibdccddilifddb" ascii wide nocase // Adblock Plus
        $s3 = "cjpalhdlnbpafiamejdnhcphjbkeiagm" ascii wide nocase // uBlock Origin
        $s4 = "epcnnfbjfcgphgdmggkamkmgojdagdnn" ascii wide nocase // uBlock
        $s5 = "kacljcbejojnapnmiifgckbafkojcncf" ascii wide nocase // Ad-Blocker
        $s6 = "gginmiamniniinhbipmknjiefidjlnob" ascii wide nocase // Easy AdBlocker
        $s7 = "alplpnakfeabeiebipdmaenpmbgknjce" ascii wide nocase // Adblocker for Chrome - NoAds
        $s8 = "ohahllgiabjaoigichmmfljhkcfikeof" ascii wide nocase // AdBlocker Ultimate
        $s9 = "lmiknjkanfacinilblfjegkpajpcpjce" ascii wide nocase // uBlocker
        $s10 = "lalfpjdbhpmnhfofkckdpkljeilmogfl" ascii wide nocase // Hola ad remover
	$s11 = "ddkjiahejlhfcafbddmgiahcphecmpfh" ascii wide nocase // uBlock Origin Lite (MV3)
	$s12 = "bgnkhhnnamicmpeenaelnjfhikgbkllg" ascii wide nocase  // AdGuard
	$s13 = "odfafepnkmbhccpbejgmiehpchacaeak" ascii wide nocase // uBlock Origin - Microsoft Edge addons store
	$s14 = "uBlock0@raymondhill.net.xpi" ascii wide nocase // uBlock Origin - Firefox
	$s15 = "uBOLite@raymondhill.net.xpi" ascii wide nocase // uBlock Origin lite - Firefox
	$s16 = "adguardadblocker@adguard.com.xpi" ascii wide nocase // AdGuard - Firefox
    condition:
        (uint16(0) == 0x5a4d and 5 of them) or (7 of them)
}

rule INDICATOR_SUSPICIOUS_GENInfoStealer {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing common artifacts observed in infostealers"
    strings:
        $f1 = "FileZilla\\recentservers.xml" ascii wide
        $f2 = "FileZilla\\sitemanager.xml" ascii wide
        $f3 = "SOFTWARE\\\\Martin Prikryl\\\\WinSCP 2\\\\Sessions" ascii wide
        $b1 = "Chrome\\User Data\\" ascii wide
        $b2 = "Mozilla\\Firefox\\Profiles" ascii wide
        $b3 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" ascii wide
        $b4 = "Opera Software\\Opera Stable\\Login Data" ascii wide
        $b5 = "YandexBrowser\\User Data\\" ascii wide
        $s1 = "key3.db" nocase ascii wide
        $s2 = "key4.db" nocase ascii wide
        $s3 = "cert8.db" nocase ascii wide
        $s4 = "logins.json" nocase ascii wide
        $s5 = "account.cfn" nocase ascii wide
        $s6 = "wand.dat" nocase ascii wide
        $s7 = "wallet.dat" nocase ascii wide
        $a1 = "username_value" ascii wide
        $a2 = "password_value" ascii wide
        $a3 = "encryptedUsername" ascii wide
        $a4 = "encryptedPassword" ascii wide
        $a5 = "httpRealm" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((2 of ($f*) and 2 of ($b*) and 1 of ($s*) and 3 of ($a*)) or (14 of them))
}
rule SUSP_Imphash_Mar23_3 {
    meta:
        description = "Detects imphash often found in malware samples (Maximum 0,25% hits with search for 'imphash:x p:0' on Virustotal) = 99,75% hits"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-23"
        modified = "2023-07-24"
        reference = "Internal Research"
        score = 45
        hash = "b5296cf0eb22fba6e2f68d0c9de9ef7845f330f7c611a0d60007aa87e270c62a"
        hash = "5a5a5f71c2270cea036cd408cde99f4ebf5e04a751c558650f5cb23279babe6d"
        hash = "481b0d9759bfd209251eccb1848048ebbe7bd2c87c5914a894a5bffc0d1d67ff"
        hash = "716ba6ea691d6a391daedf09ae1262f1dc1591df85292bff52ad76611666092d"
        hash = "800d160736335aafab10503f7263f9af37a15db3e88e41082d50f68d0ad2dabd"
        hash = "416155124784b3c374137befec9330cd56908e0e32c70312afa16f8220627a52"
        hash = "21899e226502fe63b066c51d76869c4ec5dbd03570551cea657d1dd5c97e7070"
        hash = "0461830e811d3831818dac5a67d4df736b4dc2e8fb185da439f9338bdb9f69c3"
        hash = "773edc71d52361454156dfd802ebaba2bb97421ce9024a7798dcdee3da747112"
        hash = "fe53b9d820adf3bcddf42976b8af1411e87d9dfd9aa479f12b2db50a5600f348"
        id = "eb91e700-6478-5085-a393-a7b342c0eb4f"
    condition:
        uint16(0) == 0x5A4D and (
            // no size limit as some samples are 20MB+ and the hash is calculated only on the header
            //pe.imphash() == "87bed5a7cba00c7e1f4015f1bdae2183" or // UPX imphash
            //pe.imphash() == "09d0478591d4f788cb3e5ea416c25237" or // PECompact imphash
            pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or
            pe.imphash() == "6ed4f5f04d62b18d96b26d6db7c18840" or
            pe.imphash() == "fc6683d30d9f25244a50fd5357825e79" or
            pe.imphash() == "2c5f2513605e48f2d8ea5440a870cb9e" or
            pe.imphash() == "0b5552dccd9d0a834cea55c0c8fc05be"
        )
        and pe.number_of_signatures == 0
}