rule malware_apt15_exchange_tool {
	meta:
		author = "Ahmed Zaki"
		md5 = "d21a7e349e796064ce10f2f6ede31c71"
		description = "This is a an exchange enumeration/hijacking tool used by an APT 15"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	strings:
		$s1= "subjectname" fullword
		$s2= "sendername" fullword
		$s3= "WebCredentials" fullword
		$s4= "ExchangeVersion"	fullword
		$s5= "ExchangeCredentials"	fullword
		$s6= "slfilename"	fullword
		$s7= "EnumMail"	fullword
		$s8= "EnumFolder"	fullword
		$s9= "set_Credentials"	fullword
		$s10 = "/de" 
		$s11 = "/sn" 
		$s12 = "/sbn" 
		$s13 = "/list" 
		$s14 = "/enum" 
		$s15 = "/save" 
		$s16 = "/ao" 
		$s17 = "/sl" 
		$s18 = "/v or /t is null" 
		$s19 = "2007" 
		$s20 = "2010" 
		$s21 = "2010sp1" 
		$s22 = "2010sp2" 
		$s23 = "2013" 
		$s24 = "2013sp1" 
	condition:
		uint16(0) == 0x5A4D and 15 of ($s*)
}
