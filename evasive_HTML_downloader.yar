rule evasive_HTML_downloader {
	
	meta:
		Author = "Ariel Davidpur"
		Description = "Detects HTML smuggling delivery method of malware"
		Date = "2024-07-28"
		
	strings:
		$o1 = ".click();" ascii
		$o2 = "generateCRMFRequest" ascii
		$o3 = "importScript" ascii
		$o4 = "onmouseover" ascii
		$s1 = ".download" ascii
		$s2 = "replaceAll(" ascii
		$s3 = "createObjectURL" ascii
		$s4 = "blob(" ascii
	
	condition:
		any of ($o*)
		and all of ($s*)
		}