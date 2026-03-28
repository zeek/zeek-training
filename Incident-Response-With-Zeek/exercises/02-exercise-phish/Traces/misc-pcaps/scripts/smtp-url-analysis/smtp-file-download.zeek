@load base/frameworks/files

module SMTPurl;

export {
	redef enum Notice::Type += { FileDownload, };

	global watch_mime_types: pattern = /application\/x-dosexec/ &redef;
}

event file_state_remove(f: fa_file) &priority=-3
	{
	#log_reporter(fmt("EVENT: file_state_remove: VARS: f: %s", f), 0);
	#print fmt("%s", f);

	if ( f$source != "HTTP" )
		return;
	local rec: HTTP::Info;
	local link: string = "";

	for ( c in f$conns )
		{
		rec = f$conns[c]$http;
		link = HTTP::build_url_http(rec);

		local seen = 0;
		#seen = bloomfilter_lookup(mail_links_bloom, link);

		if ( f$info?$mime_type
		    && ( link in SMTPurl::mail_links || seen > 0 )
		    && watch_mime_types in f$info$mime_type )
			{
			local cc = lookup_connection(rec$id);
			local _msg = fmt("%s", mail_links[link]);
			local fi = f$info;
			local n: Notice::Info = Notice::Info($note=FileDownload, $msg=_msg,
			    $sub=link, $conn=cc);
			Notice::populate_file_info(f, n);
			NOTICE(n);
			}
		}
	}
