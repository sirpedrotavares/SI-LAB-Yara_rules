rule Lampion_VBS_File_Portugal {
  meta:
  description = "Yara rule for Lampion Portugal - Dezember version"
  author = "SI-LAB - https://seguranca-informatica.pt"
  last_updated = "2019-12-28"
  tlp = "white"
  category = "informational"

  strings:
    $lampion_a = {53 65 74 20 76 69 61 64 6f 20 3d 20 63 75 7a 61}
    $lampion_b = {76 69 61 64 6f 2e 57 69 6e 64 6f 77 53 74 79 6c}
   
  condition:
    all of ($lampion_*) 
}
