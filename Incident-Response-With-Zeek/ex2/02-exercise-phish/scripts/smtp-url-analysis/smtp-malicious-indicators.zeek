module SMTPurl;

export {
	redef enum Notice::Type += { Malicious_MD5, Malicious_Attachment,
	    Malicious_Indicator, Malicious_Mailfrom, Malicious_Mailto,
	    Malicious_from, Malicious_reply_to, Malicious_subject,
	    Malicious_rcptto, Malicious_Path, Malicious_Decoded_Subject,
	    Malicious_URL, };

	type smtp_MaliciousIdx: record {
		indicator: string;
	};

	type smtp_maliciousVal: record {
		indicator: string;
		description: string &optional &default="null";
	};

	global smtp_malicious_indicators: table[string] of smtp_maliciousVal &redef; # todo synchronized

	# feeds for flagging sender and subject which are part of log_smtp event
	#global smtp_indicator_feed = fmt("%s/feeds/smtp_malicious_indicators.out", @DIR) &redef;
	global smtp_indicator_feed = "" &redef;
}

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == SMTPurl::Malicious_URL )
		add n$actions[Notice::ACTION_EMAIL];

	if ( n$note == SMTPurl::Malicious_MD5 )
		add n$actions[Notice::ACTION_EMAIL];

	if ( n$note == SMTPurl::Malicious_Attachment )
		add n$actions[Notice::ACTION_EMAIL];

	if ( n$note == SMTPurl::Malicious_Mailfrom )
		add n$actions[Notice::ACTION_EMAIL];

	if ( n$note == SMTPurl::Malicious_Mailto )
		add n$actions[Notice::ACTION_EMAIL];

	if ( n$note == SMTPurl::Malicious_from )
		add n$actions[Notice::ACTION_EMAIL];

	if ( n$note == SMTPurl::Malicious_reply_to )
		add n$actions[Notice::ACTION_EMAIL];

	if ( n$note == SMTPurl::Malicious_subject )
		add n$actions[Notice::ACTION_EMAIL];

	if ( n$note == SMTPurl::Malicious_rcptto )
		add n$actions[Notice::ACTION_EMAIL];

	if ( n$note == SMTPurl::Malicious_Decoded_Subject )
		add n$actions[Notice::ACTION_EMAIL];

	if ( n$note == SMTPurl::Malicious_Indicator )
		add n$actions[Notice::ACTION_EMAIL];
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( name == "smtp_malicious_indicators" )
		{
		log_reporter(fmt("EVENT: Input::update_finished: VARS: name: %s, source: %s",
		    name, source), 10);
		}
	}

event zeek_init() &priority=10
	{
	Input::add_table([ $source=smtp_indicator_feed,
	    $name="smtp_malicious_indicators", $idx=smtp_MaliciousIdx,
	    $val=smtp_maliciousVal, $destination=smtp_malicious_indicators,
	    $mode=Input::REREAD ]);
	}

event SMTP::log_smtp(rec: SMTP::Info)
	{
	#log_reporter(fmt("EVENT: SMTP::log_smtp: VARS: rec: %s", rec),10);

	if ( ! connection_exists(rec$id) )
		return;

	local c = lookup_connection(rec$id);
	local pat = />|<| /;

	if ( rec?$rcptto )
		{
		for ( rcptto in rec$rcptto )
			{
			rcptto = strip(gsub(rcptto, pat, ""));
			if ( rcptto in smtp_malicious_indicators )
				{
				NOTICE([ $note=Malicious_rcptto, $msg=fmt("Malicious rectto :: %s, %s",
				    smtp_malicious_indicators[rcptto], rcptto),
				    $email_body_sections=vector(fmt(
				    "MessageID: %s", rec$msg_id)), $conn=c,
				    $sub=rcptto, $identifier=cat(rcptto),
				    $suppress_for=1mins ]);
				}
			}
		}

	if ( rec?$to )
		{
		for ( to in rec$to )
			{
			to = strip(gsub(to, pat, ""));
			if ( to in smtp_malicious_indicators )
				{
				NOTICE([ $note=Malicious_Mailto, $msg=fmt("Malicious to:: %s, %s",
				    smtp_malicious_indicators[to], to),
				    $email_body_sections=vector(fmt(
				    "MessageID: %s", rec$msg_id)), $conn=c,
				    $sub=to, $identifier=cat(to),
				    $suppress_for=1mins ]);
				}
			}
		}

	if ( rec?$mailfrom )
		{
		local mailfrom = strip(gsub(rec$mailfrom, pat, ""));
		if ( mailfrom in smtp_malicious_indicators )
			{
			NOTICE([ $note=Malicious_Mailfrom, $msg=fmt("Malicious MailFrom :: %s, %s",
			    smtp_malicious_indicators[mailfrom], rec$mailfrom),
			    $email_body_sections=vector(fmt("MessageID: %s",
			    rec$msg_id)), $conn=c, $sub=rec$mailfrom,
			    $identifier=cat(rec$mailfrom), $suppress_for=1mins ]);
			}
		}

	if ( rec?$from )
		{
		if ( rec$from in smtp_malicious_indicators )
			{
			NOTICE([ $note=Malicious_from, $msg=fmt("Malicious Sender :: %s, %s",
			    smtp_malicious_indicators[rec$from], rec$from),
			    $email_body_sections=vector(fmt("MessageID: %s",
			    rec$msg_id)), $conn=c, $sub=rec$from,
			    $identifier=cat(rec$from), $suppress_for=1mins ]);
			}
		}

	if ( rec?$reply_to && rec$reply_to in smtp_malicious_indicators )
		{
		NOTICE([ $note=Malicious_reply_to, $msg=fmt("Malicious reply_to:: %s, %s",
		    smtp_malicious_indicators[rec$reply_to], rec$reply_to),
		    $email_body_sections=vector(fmt("MessageID: %s",
		    rec$msg_id)), $conn=c, $sub=rec$reply_to, $identifier=cat(
		    rec$reply_to), $suppress_for=1mins ]);
		}

	if ( rec?$subject && rec$subject in smtp_malicious_indicators )
		{
		NOTICE([ $note=Malicious_subject, $msg=fmt("Malicious Subject:: %s, %s",
		    smtp_malicious_indicators[rec$subject], rec$subject),
		    $email_body_sections=vector(fmt("MessageID: %s",
		    rec$msg_id)), $conn=c, $sub=rec$subject, $identifier=cat(
		    rec$subject), $suppress_for=1mins ]);
		}

	#	if (rec?$decoded_subject && rec$decoded_subject in smtp_malicious_indicators)
	#        {
	#                NOTICE([$note=Malicious_Decoded_Subject, $msg=fmt("Known Malicious Decoded Subject:: %s %s, %s, %s", smtp_malicious_indicators[rec$decoded_subject], rec$decoded_subject, rec$from, rec$to),
	#                                                                $conn=c, $sub=rec$decoded_subject, $identifier=cat(rec$decoded_subject),$suppress_for=1 mins]);
	#        }

	##### path is a vector of addr
	if ( rec?$path )
		{
		for ( path in rec$path )
			{
			local ip = fmt("%s", rec$path[path]);
			if ( ip in smtp_malicious_indicators )
				{
				NOTICE([ $note=Malicious_Path, $msg=fmt(
				    "Blacklisted IP in smtp relay Path: %s %s",
				    smtp_malicious_indicators[ip], ip),
				    $email_body_sections=vector(fmt(
				    "MessageID: %s", rec$msg_id)), $conn=c,
				    $sub=ip, $identifier=cat(ip),
				    $suppress_for=1mins ]);
				}
			}
		}
	}
##### end of policy

event file_state_remove(f: fa_file) &priority=-3
	{
	if ( f$source != "SMTP" )
		return;

	local rec: SMTP::Info;

	for ( c in f$conns )
		{
		rec = f$conns[c]$smtp;

		if ( f$info?$filename && f$info$filename in smtp_malicious_indicators )
			{
			local cc = lookup_connection(rec$id);
			local _msg = fmt("Malicious attachment");
			local fi = f$info;
			local n: Notice::Info = Notice::Info($note=Malicious_Attachment,
			    $email_body_sections=vector(fmt("MessageID: %s",
			    rec$msg_id)), $msg=_msg, $sub=f$info$filename,
			    $conn=cc);
			Notice::populate_file_info(f, n);
			NOTICE(n);
			}
		}
	}

module TeamCymruMalwareHashRegistry;

@ifndef ( TeamCymruMalwareHashRegistry::Match )
@load policy/frameworks/files/detect-MHR.zeek
@endif
event file_hash(f: fa_file, kind: string, hash: string)
	{
	if ( kind == "sha1" && f?$info && f$info?$filename
	    && f$info$filename in SMTPurl::smtp_malicious_indicators )
		{
		print fmt("HEREEEEEEEEEEEEEEEEE");
		TeamCymruMalwareHashRegistry::do_mhr_lookup(hash, Notice::create_file_info(f));
		}
	}

module SMTPurl;

event SMTPurl::process_smtp_urls(c: connection, url: string)
	{
	if ( url in smtp_malicious_indicators )
		NOTICE([ $note=Malicious_URL, $msg=fmt("Malicious URL: %s, %s", url, c$smtp),
		    $email_body_sections=vector(fmt("MessageID: %s",
		    c$smtp$msg_id)), $conn=c, $sub=url, $identifier=cat(url),
		    $suppress_for=1mins ]);
	}
