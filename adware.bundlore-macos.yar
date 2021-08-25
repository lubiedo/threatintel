rule Bundlore_Bnodlero : Adware MacOS {
  meta:
    author = "@_lubiedo"
    date   = "25-08-2021"
    hash00 = "7a1669c76c62f088145a53058aac88f1ba555c776931cfb11e917a7789c9f81c"
  strings:
    $h00  = "#!/bin/sh"
    $h01  = { 50 4B 03 04 }
    $s01  = "Install Flash Player"
    $s02  = "nVroe"
    $s03  = "8456"
  condition:
    filesize < 100KB and ($h00 at 0 and $h01) and all of ($s*)
}

rule Bundlore_Bnodlero2 : Adware MacOS {
  meta:
    author = "@_lubiedo"
    date   = "25-08-2021"
    hash00 = "b69ae4192ee3602a9e22ca37201cc2c18b37479b5965ef745fcbfd5ca441393c"
  strings:
    $c00   = { EC 98 B4 92 F6 BE FF 0F 01 9D 05 13 02 B9 EC 4D }
    $c01   = { 48 8B 05 3B 2D 00 00 FF E0 }
  condition:
    filesize < 100KB and uint32be(0) == 0xCFFAEDFE and all of ($c*)
}

rule Bundlore_Bnodlero3 : Adware MacOS {
  meta:
    author = "@_lubiedo"
    date   = "25-08-2021"
  strings:
    $s00   = "/usr/bin/sqlite3"
    $s01   = "/.did" nocase
    $s02   = "sidw"
    $s03   = "neo"
    $s04   = "utm_source"
    $s05   = "com.apple.LaunchServices.QuarantineEventsV2" nocase
    $s06   = "Installer.app.zip" nocase
  condition:
    filesize < 100KB and all of ($s*)
}

