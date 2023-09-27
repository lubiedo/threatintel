
rule ransomware_XX_RansomHouse_Mario {
  meta:
    author      = "@_lubiedo"
    date        = "26-09-2023"
    description = "https://twitter.com/1ZRR4H/status/1706408515223392420"
    hash0       = "d36afcfe1ae2c3e6669878e6f9310a04fb6c8af525d17c4ffa8b510459d7dd4d"
  strings:
    $s00 = "Encrypting: %s\n" fullword
    $s01 = "Welcome to the RansomHouse"
    $s02 = "How To Restore Your Files.txt"
    $s03 = ".mario"
    $s04 = ".emario"
    $s05 = "START: %s\n"

    // formats
    $f01 = ".vmk"
    $f02 = ".ovf"
    $f03 = ".ova"
    $f04 = ".vmem"
    $f05 = ".vswp"
    $f06 = ".vmsd"
    $f07 = ".vmsn"
    $f08 = ".vib"
    $f09 = ".vbk"
    $f10 = ".vbm"

    // extension comparison
    $cmp = { 48 8B 45 E0 48 83 C0 13 48 8D 35 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 85 C0 }

  condition:
    filesize < 100KB and uint32be(0) == 0x7F454C46 and
    ( all of ($s*)  and 3 of ($f*) and #cmp > 3 )
}

