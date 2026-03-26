module SMTPurl;

export {
	global STATS_TIME: interval = 10mins;

	redef enum Notice::Type += { WRITER_POSTGRESQL_CRASH, };
}

event zeek_done()
	{
	return;

	for ( a in AddressBook )
		print fmt("Addressbook: %s", a);

	for ( l in smtp_from )
		print fmt("%s", smtp_from[l]);

	for ( l in smtp_from_name )
		print fmt("FROM_NAMEEEEEE: %s", smtp_from_name[l]);

	for ( l in smtp_from_email )
		print fmt("FROM_EMAIL: %s", smtp_from_email[l]);
	}

event zeek_done()
	{
	return;

	print fmt("########### from_name #################");
	for ( from_name in smtp_from_name )
		print fmt("%s -> %s", from_name, smtp_from_name[from_name]);

	print fmt("########### from_email #################");
	for ( from_email in smtp_from_email )
		print fmt("%s -> %s", from_email, smtp_from_email[from_email]);

	print fmt("########### smtp_from #################");
	for ( from in smtp_from )
		print fmt("%s -> %s", from, smtp_from[from]);

	for ( to_name in email_recv_to_name )
		print fmt("TO_NAME: %s, %s", to_name, email_recv_to_name[to_name]);

	for ( to_email in email_recv_to_address )
		print fmt("TO_EMAIL: %s, %s", to_email, email_recv_to_address[to_email]);
	}

event log_stats()
	{
	log_reporter(fmt("STATS: mail_links: %s, smtp_from: %s, smtp_from_name: %s, smtp_from_email: %s, http_fqdn: %s, email_recv_to_name: %s, email_recv_to_address: %s",
	    |SMTPurl::mail_links|, |SMTPurl::smtp_from|,
	    |SMTPurl::smtp_from_name|, |SMTPurl::smtp_from_email|,
	    |SMTPurl::http_fqdn|, |SMTPurl::email_recv_to_name|,
	    |SMTPurl::email_recv_to_address|), 0);
	schedule STATS_TIME { SMTPurl::log_stats() };
	}

event zeek_init()
	{
	schedule STATS_TIME { SMTPurl::log_stats() };
	}

event reporter_error(t: time, msg: string, location: string)
	{
	print fmt("EVENT: bro-done Reporter ERROR: %s, %s, %s", t, msg, location);

	if ( /WRITER_POSTGRESQL/ in msg )
		{
		NOTICE([ $note=SMTPurl::WRITER_POSTGRESQL_CRASH, $msg=msg ]);
		}
	}
