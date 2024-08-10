rule self_location_with_email {

	meta:
		Author = "Ariel Davidpur"
		Description = "Finds self.location function with URL that ends with email address"
		Hash = "934d9fa337cb4f0a89e92a909d4147a66355df619da2d6ce05c50e483d4957fd"
		Date = "2024-08-09"
	
	strings:
		$re1 = /^self\.location\s*?=\s*?['\"]https:\/\/.+?\b[\w\.-]+?@[\w-]+?\.\w+?\b['\"]\s*?;\s*?$/i
		$re2 = /^self\.location\s*?=\s*?['\"]http:\/\/.+?\b[\w\.-]+?@[\w-]+?\.\w+?\b['\"]\s*?;\s*?$/i
	
	condition:
		any of them
}