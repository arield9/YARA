rule search_query_href{
	meta:
		Author = "Ariel Davidpur"
		Description = "Should help detect use of cve-2024-21412, which uses Search Query in HREF tag"
		Date = "2024-08-01"
	
	strings:
		$re1 = /href\s*?=\s*?['\"]search\:query\s*?=[^>]*?location\:\\\\/i
	
	condition:
		$re1
}