rule login_page_tags {

	meta:
		Author = "Ariel Davidpur"
		Description = "This rule should detect login page tags in HTML file"
		Date = "July 23rd 2024"
		
	strings:
		$s1 = "type=\"password\""
		$s2 = "type=\"email\""
	
	condition:
		all of ($s*)
	}
