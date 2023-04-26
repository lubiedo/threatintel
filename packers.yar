rule jiagu : android {
  meta:
    author      = "@_lubiedo"
  strings:
    $s00 = { 71 68 ?? ?? ?? ?? ?? ?? be 03 }
  condition:
    filesize < 2MB and uint32be(0) == 0x6465780a and all of ($s*)
}

