rule rule1 {
			meta:
			author = "Emanuel Valente"
			description = "Yara rule for testing purposes"
			
			strings:
			$a = "skype.dat" ascii
			$b = "emanuel" ascii
			
			condition:
			$a and $b
		}
