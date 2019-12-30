import "hash"

rule Lampion_malware_portugal {
  meta:
  description = "Yara rule for Lampion Portugal - December version"
  author = "SI-LAB - https://seguranca-informatica.pt"
  last_updated = "2019-12-28"
  tlp = "white"
  category = "informational"

  strings:
    $lampion_a = {3f 3f 3f 3f 3f 3f 3f 74 61 3f 3f 3f 3f 3f 3f 00}

  condition:
    all of ($lampion_*) or
    hash.md5(0, filesize) == "18977c78983d5e3f59531bd6654ad20f"
}
