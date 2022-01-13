rule Sysjoker_Dropper_Win : Backdoor {
  meta:
    author = "@_lubiedo"
    date   = "13-01-2022"
    hash   = "61df74731fbe1eafb2eb987f20e5226962eeceef010164e41ea6c4494a4010fc"
    reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
  strings:
    $s00 = "https://github.url-mini.com/msg.zip" fullword
    $s01 = "\\recoveryWindows.zip" fullword nocase
    $s02 = "powershell.exe Invoke-WebRequest -Uri" nocase
    $s03 = "';Write-Output \"Time taken : $((Get - Date).Subtract($start_time).Seconds) second(s)\"" fullword nocase
  condition:
    filesize < 400KB and uint16be(0) == 0x4D5A and all of ($s*)
}

rule Sysjoker_Backdoor_Win : Backdoor {
  meta:
    author = "@_lubiedo"
    date   = "13-01-2022"
    hash   = "1ffd6559d21470c40dcf9236da51e5823d7ad58c93502279871c3fe7718c901c"
    reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
  strings:
    $s00 = "Set-Cookie:\\b*{.+?}\\n" fullword wide nocase
    $s02 = /\\(txc|temp[osi])[0-9]\.txt/ nocase
    $s03 = "wmic path win32_physicalmedia get SerialNumber"
    $s04 = "&user_token=8723478873487" fullword nocase
    $s05 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0" fullword wide
    $s06 = "IGFXCUISERVICE.EXE" fullword wide
  condition:
    filesize < 500KB and uint16be(0) == 0x4D5A and all of ($s*)
}

rule Sysjoker_Backdoor_macOS : Backdoor {
  meta:
    author = "@_lubiedo"
    date   = "13-01-2022"
    hash   = "1a9a5c797777f37463b44de2b49a7f95abca786db3977dcdac0f79da739c08ac"
    reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
  strings:
    $s00 = "https://drive.google.com/uc?export=download&id=1W64PQQxrwY3XjBnv_QAeBQu-ePr537eu" fullword
    $s01 = "updateMacOS" fullword nocase
    $s02 = "&user_token=987217232" fullword
    $s03 = "/Library/LaunchAgents/com.apple.update.plist" fullword
    $s04 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15" fullword
  condition:
    filesize < 500KB and uint32be(0) == 0xCAFEBABE and all of ($s*)
}

rule Sysjoker_Backdoor_Linux : Backdoor {
  meta:
    author = "@_lubiedo"
    date   = "13-01-2022"
    hash   = "1a9a5c797777f37463b44de2b49a7f95abca786db3977dcdac0f79da739c08ac"
    reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
  strings:
    $s00 = "ip address | awk '/ether/{print $2}'" fullword
    $s01 = "uname -mrs" fullword
    $s02 = "&user_token=987217232" fullword
    $s03 = "before addToStatup" fullword
    $s04 = "ifconfig | grep -v 127.0.0.1 | grep -E \"inet ([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\" | awk '{print $2}'" fullword
  condition:
    filesize < 2MB and uint32be(0) == 0x7F454C46 and all of ($s*)
}
