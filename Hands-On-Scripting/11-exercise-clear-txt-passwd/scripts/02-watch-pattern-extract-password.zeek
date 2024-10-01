module OUO;

export {
	redef enum Notice::Type += {
		MsgBody,
	};

	global keyword_blob: pattern = /.{0,90}password.{0,190}/ &redef ; 
	global keywords: pattern = /(?i:password)/ ; 

	global interesting_files: set[string] ;
}


event mime_all_data(c: connection, length: count, data: string) &priority=-5
	{
	if (! c?$smtp)
		return ;

	if ( keyword_blob in data)
	{
		local match = find_all (data, keyword_blob);
		local hits = ""  ;

		print fmt ("%s", match); 

		for (m in match) {
			hits += fmt ("match: %s ", m) ;
		}

		local rcpt= "" ;

		for (a in c$smtp$rcptto)
			rcpt += fmt ("%s %s", rcpt, a) ;

		local keyword_match = find_all(hits, keywords);
		local keyword_hits : set[string] ;
		local kh="" ;

		for (k in keyword_match) {
			add keyword_hits[k];
		}

		for (v in keyword_hits)
			kh += fmt (" %s ", v) ;

		NOTICE([$note=MsgBody, $msg=fmt("%s #  %s #  %s # %s # %s # %s",c$smtp$ts, c$smtp$mailfrom, rcpt, c$smtp$subject, kh, hits ), $conn=c]);
	}
	}

