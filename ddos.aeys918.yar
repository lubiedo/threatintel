rule Aeys_918 : DDoS {
  meta:
    author      = "@_lubiedo"
    date        = "11-11-2021"
    hash0       = "d456f84b942e3b8f188b834926ab9ca004894bc9811e8508fd8eb7e77001817b"
  strings:
    $s00 = "Starting flood...by:Aeys 918\n" fullword
    $s01 = "192.168.3.100" fullword
    // 00400e8f  bf2e160000         mov     edi, 0x162e
    $c00 = { BF 2E 16 00 00 } // exit(-1)
    // 00400ea0  bfcb2b0000         mov     edi, 0x2bcb
    $c01 = { BF CB 2B 00 00 }
  condition:
    filesize < 100KB and ( all of ($s*) or all of ($c*) )
}

