import "pe"

rule Brazilian_trojan_Portugal_april_2020 {
  meta:
  description = "Yara rule for Brazilian Trojan Portugal - May version"
  author = "SI-LAB @sirpedrotavares - https://seguranca-informatica.pt"
  last_updated = "2020-05-05"
  tlp = "white"
  category = "informational"

  strings:
    $trojan_a = {42 61 6E 63 6F 42 70 69}
    $trojan_b = {4D 69 6C 6C 65 6E 69 75 6D 42 63 70}

  condition:
    all of ($trojan_*) and pe.number_of_sections > 6
}
