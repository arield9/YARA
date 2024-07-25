rule base64_atob{
	
	meta:
		Author = "Ariel Davidpur"
		Description = "evidence for \"atob()\" function in HTML file source code"
		Date = "July 23rd 2024"
	
	strings:
		$s = "atob(" base64
	
	condition:
		$s
	}
