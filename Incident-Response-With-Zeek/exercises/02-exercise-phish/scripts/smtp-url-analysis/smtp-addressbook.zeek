module SMTPurl;

export {
	redef enum Notice::Type += { AllGood, PotentialSMTPurl, NameSpoofing, Weird,
	    NewContact, MassUnknownSender, };

	type name_rec: record {
		name: string &optional &log;
		email: string &log;
	};

	global mail_handshake: table[string, string] of count &default=0;
	#global AddressBook: table[string] of addressbook_rec ;
	global check_addressbook_anomalies: function(sender_name: string,
	    sender_email: string, recipient_name: string,
	    recipient_email: string, uid: string, id: conn_id);
	global handshake_bloom: opaque of bloomfilter;
	global unknown_sender: table[string] of set[string] &create_expire=5days;
	global check_for_unknown_sender: function(sender_email: string,
	    recipient_email: string);
}

function add_to_addressbook(owner_name: string, owner_email: string,
    entry_name: string, entry_email: string)
	{
	log_reporter(fmt("Processing %s, %s", owner_name, owner_email), 0);

	# initialize AB for the owner if not already
	if ( owner_email !in AddressBook )
		{
		local a_rec: addressbook_rec;
		local a_entry: set[string];
		a_rec = [ $owner_email=owner_email, $owner_name=owner_name, $entry=a_entry ];
		AddressBook[owner_email] = a_rec;
		}

	local e = fmt("%s,%s", entry_name, entry_email);
	if ( e !in AddressBook[owner_email]$entry )
		{
		add AddressBook[owner_email]$entry[e];
		sql_write_addressbook_db(AddressBook[owner_email]);

		#	local _msg = fmt ("%s [%s] has new contact %s [%s]", owner_name, owner_email, entry_name, entry_email);
		#	NOTICE([$note=NewContact, $msg=_msg ]);
		}
	}

function check_addressbook_anomalies(sender_name: string, sender_email: string,
    recipient_name: string, recipient_email: string, uid: string, id: conn_id)
	{
	local sender_name_trustworthy = ( sender_name in smtp_from_name ) ?
	    smtp_from_name[sender_name]$trustworthy : F;
	local sender_email_trustworthy: bool = ( sender_email in smtp_from_email ) ?
	    smtp_from_email[sender_email]$trustworthy : F;

	local s = fmt("%s,%s", sender_name, sender_email);

	### check if sender is in recipient's addressbook
	if ( s in AddressBook[recipient_email]$entry )
		{
		for ( e in AddressBook[recipient_email]$entry )
			{
			local parts = split_string(e, /,/);
			local address_name = to_lower(parts[0]);

			local address_email = ( |parts| == 2 ) ? to_lower(parts[1]) : "";

			local _msg = fmt("sender_name: %s, from_address: %s, address_name: %s, address_email: %s",
			    sender_name, sender_email, address_name,
			    address_email);

			#if (address_name == sender_name && address_email != sender_email && sender_name_trustworthy && !sender_email_trustworthy )

			if ( address_name == sender_name && address_email != sender_email )
				{
				_msg += fmt(" BAD - spoof");
				_msg += fmt("Other Entries: %s", smtp_from_name[sender_name]);
				NOTICE([ $note=PotentialSMTPurl, $msg=_msg, $uid=uid, $id=id ]);
				}

			if ( address_name != sender_name && address_email == sender_email )
				{
				_msg += fmt(" Weird");
				NOTICE([ $note=Weird, $msg=_msg, $id=id ]);
				}
			if ( address_name == sender_name && address_email == sender_email )
				{
				_msg += fmt(" ALL GOOD");
				NOTICE([ $note=AllGood, $msg=_msg, $id=id ]);
				}

			# this is lame so deleting
			#if (address_name != sender_name && address_email != sender_email )
			}
		}
	else
		{
		check_for_unknown_sender(sender_email, recipient_email);
		}
	}

function check_for_unknown_sender(sender_email: string, recipient_email: string)
	{
	if ( sender_email !in unknown_sender )
		{
		unknown_sender[sender_email] = set();
		}

	add unknown_sender[sender_email][recipient_email];

	local size = |unknown_sender[sender_email]|;

	if ( size > 400 )
		NOTICE([ $note=MassUnknownSender, $msg=fmt(
		    "Unknown sender %s sending to %s recipients", sender_email,
		    size), $suppress_for=10secs, $identifier=sender_email ]);
	}

function SMTPurl::process_addressbook(rec: SMTP::Info)
	{
	#log_reporter(fmt("EVENT: SMTPurl::w_m_smtp_rec_new : VARS: rec: %s", rec),0);

	local sender_email = rec?$from ? get_email_address(rec$from) : "";
	local sender_name = rec?$from ? get_email_name(rec$from) : sender_email;

	local sender_name_trustworthy = ( sender_name in smtp_from_name ) ?
	    smtp_from_name[sender_name]$trustworthy : F;
	local sender_email_trustworthy: bool = ( sender_email in smtp_from_email ) ?
	    smtp_from_email[sender_email]$trustworthy : F;

	# if sender is trustworthy we check for compromised account
	if ( sender_name_trustworthy && sender_email_trustworthy )
		{
		return;
		# eventually we check for compromised account phish
		#check_for_compromised_login_anomaly(rec);
		}

	if ( sender_name_trustworthy && ! sender_email_trustworthy )
		{
		local _msg = fmt("sender_name: %s, sender_email: %s,rec : %s", sender_name,
		    sender_email, rec);
		NOTICE([ $note=NameSpoofing, $msg=_msg, $uid=rec$uid, $id=rec$id ]);
		}

	if ( rec?$to )
		{
		for ( to in rec$to )
			{
			local recipient_name = get_email_name(to);
			local recipient_email = get_email_address(to);

			# check recipient addressbook for sender anomalies
			if ( recipient_email in AddressBook )
				check_addressbook_anomalies(sender_name, sender_email, recipient_name,
				    recipient_email, rec$uid, rec$id);
			else
				check_for_unknown_sender(sender_email, recipient_email);

			if ( [ sender_email, recipient_email ] !in mail_handshake )
				mail_handshake[sender_email, recipient_email] = 0;

			mail_handshake[sender_email, recipient_email] += 1;

			if ( [ recipient_email, sender_email ] in mail_handshake )
				{
				### TODO: now since recipient_email has responded to sender_email
				### lets also add sender_email to recipient_email's addressbook as well
				#add_to_addressbook(sender_name, sender_email, recipient_name, recipient_email);

				add_to_addressbook(recipient_name, recipient_email, sender_name,
				    sender_email);
				}
			}
		}
	}

event zeek_init()
	{
	handshake_bloom = bloomfilter_basic_init(0.001, 1000000);
	}
