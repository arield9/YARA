rule greatness_kit{
	
	meta:
		Author = "Ariel Davidpur"
		Description = "Detects indicators for greatness phishing kit in source code"
		date = "July 25th 2024"
	
	strings:
		$s1 = /\/admin\/js\/[a-z]{2}\.php/i
		$s2 = "/admin/js/ms.php" base64
		$s3 = "/admin/js/mj.php" base64
		$s4 = "/admin/js/mf.php" base64
		$s5 = "/admin/js/mp.php" base64
		$s6 = "/admin/js/sc.php" base64
		
	condition:
		any of ($s*)
}