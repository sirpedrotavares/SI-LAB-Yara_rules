import "hash"

rule Lampion_DLL_Portugal {
  meta:
  description = "Yara rule for Lampion Portugal - December version"
  author = "SI-LAB - https://seguranca-informatica.pt"
  last_updated = "2019-12-28"
  tlp = "white"
  category = "informational"

  strings:
    $lampion_a = {5468 6973 4269 6368 7400 4669 6c74 6572}

  condition:
    all of ($lampion_*) or
    hash.md5(0, filesize) == "76eed98b40db9ad3dc1b10c80e957ba1"
}
