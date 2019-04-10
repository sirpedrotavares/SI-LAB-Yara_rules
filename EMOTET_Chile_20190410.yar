import "pe"

rule EMOTET_Chile {
  meta:
  description = "Yara rule for EMOTET Chile - April version"
  author = "SI-LAB - https://seguranca-informatica.pt"
  last_updated = "2019-04-10"
  tlp = "white"
  category = "informational"

  strings:
    $emotet_chile_a = {31 A8 31 AC 31 B0 31 28}
    $emotet_chile_b = {00 69 00 67 00 52 00 65 00 64}
    $emotet_chile_c = {44 65 6C 70 68 69}
    $emotet_chile_d = {64 76 33 48 82 48 46 38 5C 08 B0 25}

  condition:
    all of ($emotet_chile_*) and pe.number_of_sections == 6 and (pe.version_info["CompanyName"] contains "BigRed" and pe.version_info["OriginalFilename"] contains "BigRed") and (pe.version_info["FileDescription"] contains "BigRed")
}
