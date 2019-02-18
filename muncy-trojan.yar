import "pe"

rule Muncy_Trojan_201902 {
meta:
	description = "Yara rule for Trojan Trojan:Win32/Azden.A!cl - February version"
	author = "SI-LAB - https://seguranca-informatica.pt"
	last_updated = "2019-02-12"
	tlp = "white"
	category = "informational"
strings:
	$a1 = "DOMICILIATING2" 
	$a2 = "chokepoint"
	$a3 = "kalie"
condition:
	all of ($a*) and pe.number_of_sections == 3 and (pe.version_info["OriginalFilename"] contains "Muncy.exe" and pe.version_info["ProductName"] contains "HARPALUS8") or (pe.version_info["OriginalFilename"] contains "	NUMA10.exe")
 }


