rule daddyl33t : Yakuza Botnet Mirai Gafgyt {
  meta:
    author      = "@_lubiedo"
    date        = "09-09-2021"
    description = "https://twitter.com/albertzsigovits/status/1435922959483510793"
    hash0       = "37009587fb1ca7d7764e5394c705bc83b1aaf8cd2157af46a32bb05bea45b29a"
  strings:
    $s00 = "YakuzaBotnet" fullword nocase
    $s01 = "daddyl33t's back" fullword
    $s02 = "KAFFER-SLAP" fullword
    $s03 = "GAME-KILLER" fullword
    $s04 = "CHOOPA" fullword

    $c00 = { 41 4C 4C 00 } // ALL
    $c01 = { 53 59 4E 00 } // SYN
    $c02 = { 50 53 48 00 } // PSH

    $x00 = "/cdn-cgi/l/chk_captcha"
    $x01 = "/45xUdHPiFHQ7xbKh19G45saF1raB2ot5pag8p1Hnk4yrfXRJZskr8TMbFpVfC5tDk8eQQg63TqkW9gKhwagx6HePTaK2yXb/x4c/x3a/x50/x51/x20/x71/x5b/x7a/"
  condition:
    filesize < 200KB and uint32be(0) == 0x7f454c46 and (
      3 of ($s*) and ( any of ($x*) or 3 of ($c*) )
    )

}

