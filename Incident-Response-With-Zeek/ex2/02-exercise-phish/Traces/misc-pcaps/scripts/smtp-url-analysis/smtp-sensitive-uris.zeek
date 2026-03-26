module SMTPurl;

export {
	redef enum Notice::Type += {
		# decomissioned
		#Embedded_Malicious_URL,

		SensitiveURI,
		DottedURL,
		Suspicious_File_URL,
		Suspicious_Embedded_Text,
		WatchedFileType,
		BogusSiteURL,
	};

	global link_already_seen: set[string] &create_expire=1day &redef;

	global suspicious_file_types: pattern = /\.pdf/ &redef;
	global ignore_file_types: pattern = /\.png/ &redef;
	option ignore_fp_links: pattern = /www\.es\.net/ &redef;

	global ignore_mail_originators: set[subnet] &redef;
	global ignore_mailfroms: pattern = /example@example.com/ &redef;
	global ignore_notification_emails: set[string] &redef;
	global ignore_site_links: pattern = /www\.lbl\.gov\// &redef;

	global suspicious_text_in_url: pattern = /exploit/ &redef;
}

hook Notice::policy(n: Notice::Info)
	{ #if ( n$note == SMTPurl::BogusSiteURL)
	#{
	#add n$actions[Notice::ACTION_EMAIL];
	#}

	#if ( n$note == SMTPurl::HTTPSensitivePOST)
	#      {
	#            add n$actions[Notice::ACTION_EMAIL];
	#      }
	}

event SMTPurl::process_smtp_urls(c: connection, url: string)
	{
	log_reporter(fmt(
	    "EVENT: SMTPurl::process_smtp_urls: sensitiveURIs VARS: url: %s",
	    url), 10);

	if ( ! c?$smtp )
		return;

	if ( c$smtp?$mailfrom && ignore_mailfroms in c$smtp$mailfrom )
		return;

	if ( c$smtp?$to )
		{
		for ( to in c$smtp$to )
			{
			if ( ignore_mailfroms in to )
				return;
			}
		}

	if ( ! c?$smtp )
		return;

	if ( c$id$orig_h in ignore_mail_originators )
		return;

	local link = url;
	local domain = extract_host(link);

	if ( ignore_file_types !in link && ignore_fp_links !in link )
		{
		if ( suspicious_file_types in link )
			{
			NOTICE([ $note=WatchedFileType, $msg=fmt(
			    "Suspicious filetype embeded in URL %s from  %s",
			    link, c$id$orig_h), $conn=c ]);
			}
		if ( suspicious_text_in_url in link )
			{
			NOTICE([ $note=SensitiveURI, $msg=fmt(
			    "Suspicious text embeded in URL %s from  %s", link,
			    c$smtp$uid), $conn=c ]);
			}
		if ( /\/([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}\// in link )
			{
			NOTICE([ $note=DottedURL, $msg=fmt("Embeded IP in URL %s from  %s", link,
			    c$id$orig_h), $conn=c ]);
			}
		if ( SMTPurl::site_domain in domain && SMTPurl::site_sub_domains !in domain )
			{
			NOTICE([ $note=BogusSiteURL, $msg=fmt(
			    "Very similar URL to site: %s from  %s", link,
			    c$id$orig_h), $conn=c ]);
			}
		}
	}
