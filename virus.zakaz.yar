rule Zakaz_Windows : Virus MBR{
  meta:
    author      = "@_lubiedo"
    date        = "06-12-2022"
    description = "Zakaz (MBR killer) Virus"
    hash0       = "c51878eddd76bbe81e9bd5e15222440bd380845fae5342eaa8208ee039f458fb"
    ref0        = "https://twitter.com/siri_urz/status/1600119692902862848"
  strings:
      $s00 = "\\\\.\\PhysicalDrive0" fullword wide
      $c01 = {68 00 02 00 00 8D 44 24 14 6A 00 50 E8 14 0F 00 00 83 C4 14 6A 00 6A 00 6A 03 6A 00 6A 03 68 00 00 00 10 68 44 31 40 00 FF 15 04 30 40 00 6A 00 8D 4C 24 08 51 68 00 02 00 00 8D 4C 24 14 51 50 FF 15 00 30 40 00}
  condition:
    filesize < 50KB and uint16be(0) == 0x4D5A and all of them
}