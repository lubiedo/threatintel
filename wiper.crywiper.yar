rule CryWiper_Wiper_Windows : Wiper Packed {
  meta:
    author      = "@_lubiedo"
    date        = "05-12-2022"
    description = "CryWiper"
    hash0       = "307a61c288932ffeb7a25d667cf2911266c5379acfab20aa9a52c1aa1148d59b"
    ref0        = "https://securelist.ru/novyj-troyanec-crywiper/106114/"

  strings:
    $upx = "UPX!"
    $s00 = "HOW TO DECRYPT FILES" fullword
    $s01 = "ComSpec" fullword
    $s02 = "/c del \"" fullword
    $s03 = "motherfuck!"
    $s04 = "VirtualAlloc" fullword
    $s05 = "CreateFontIndirectA" fullword
  condition:
    filesize < 50KB and uint16be(0) == 0x4D5A and $upx in (0..1024)
        and all of ($s*)
}

rule CryWiper_Unpacked_Wiper_Windows : Wiper {
  meta:
    author      = "@_lubiedo"
    date        = "05-12-2022"
    description = "CryWiper Unpacked"
    hash0       = "ec09cfa4a79d709daed859d1a0e131aaa994f4a7b4bed80406125db76446fbda"
    ref0        = "https://securelist.ru/novyj-troyanec-crywiper/106114/"

  strings:
    $key = { 5D B3 00 CC 8C 04 EC EE D0 32 12 EA EB 92 8F 47 }
    $xor = { 83 FA 10 75 ?? 33 D2 AC 32 04 1A AA 42 49 75 ?? }

    $s00 = "CRYPTED!" fullword
    $s01 = "HOW TO DECRYPT FILES.txt" fullword
    $s02 = "CryptCreateHash" fullword
    $s03 = "LoadResource" fullword
    $s04 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword
  condition:
    filesize < 500KB and uint16be(0) == 0x4D5A and (
        ($key and $xor) or all of ($s*))
}

