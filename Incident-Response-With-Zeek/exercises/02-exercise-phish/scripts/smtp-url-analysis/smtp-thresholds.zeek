#redef exit_only_after_terminate=T;

module SMTPurl;

# to do :
# same subject: too many recipients
# same sender: too many subjects

export {

	redef enum Notice::Type += { TargetedSubject, bcc_HighVolumeSubject,
	    SubjectMassMail,
		InternalBCCSender, InternalMassMail,
		ExternalBCCSender, ExternalMassMail,
		SMTP_Invalid_rcptto,
		ManyMsgOrigins, };

	type smtp_thresholds: record {
		start_time: time;
		end_time: time;
		mailfrom: string;
		from: set[string];
		to: set[string];
		rcptto: set[string];
		subject: vector of string;
		reply_to: set[string];
		bcc: set[string];
		urls: set[string];
		attachments: set[string];
		msg_origin_ip: set[addr];
	};

	global smtp_activity: table[string] of smtp_thresholds &create_expire=4hrs; # zeek porting &persistent;

	type smtp_subjects: record {
		sender: set[string];
		recipients: set[string];
	};

	global smtp_subject_activity: table[string] of smtp_subjects &create_expire=4hrs; # zeek porting  &persistent ;

	# code for threshold determination

	const smtp_threshold: vector of count = { 50, 100, 250, 500, 750, 1000, 2000,
	    5000, 7500, 10000, 20000, 50000, 1000000,  } &redef;

	global smtp_to_threshold_idx: table[string] of count &default=0 &write_expire=1day
	    &redef;

	const smtp_subject_threshold: vector of count = { 25, 50, 100, 150, 200, 300,
	    500, 750, 1000, 5000, 10000,  } &redef;

	global smtp_subject_threshold_idx: table[string] of count &default=0
	    &write_expire=1day &redef;

	# prepare to digest data from feeds
	type BulkSenderIdx: record {
		mailfrom: string;
	};

	type BulkSenderVal: record {
		mailfrom: string;
		#comment: string &optional &default="null";
	};

	global ok_bulk_sender: table[string] of BulkSenderVal = table() &redef; # zeek porting synchronized

	global ok_bulk_sender_ip_feed = fmt("%s/feeds/ok_bulk_senders.out", @DIR) &redef;

	global ignore_smtp_subjects: pattern = /phenixbb/ &redef;

	global check_smtp_thresholds: function(rec: SMTP::Info);

	global email_domain = /XXXX/ &redef;
	global site_email: pattern = /@(.*\.)?lbl\.gov|@nersc\.gov|@es\.net/ &redef;

	const SUBJECT_THRESHOLD = 50;

	global IS_BCC: bool = F;
	global pat = />|<| |\"|\'/;
} #end of export

function thresh_check(v: vector of count, idx: table[string] of count,
    orig: string, n: count): bool
	{
	if ( idx[orig] < |v| && n >= v[idx[orig]] )
		{
		++idx[orig];
		return ( T );
		}
	else
		return ( F );
	}

function duration_to_hour_mins_secs(dur: interval): string
	{
	if ( dur < 0sec )
		return fmt("%dh%dm%ds", 0, 0, 0);

	local dur_count = double_to_count(interval_to_double(dur));
	local hour = dur_count / 3600;
	local _mins = dur_count - ( ( dur_count / 3600 ) * 3600 );
	return fmt("%dh%dm%ds", hour, _mins / 60, _mins % 60);
	}

function clean_sender(sender: string): string
	{
	#local pat = />|<| |\"|\'/;
	local to_n = split_string(sender, /</);

	local to_name: string;

	if ( |to_n| == 1 )
		{
		to_name = strip(gsub(to_n[0], pat, ""));
		}
	else
		{
		to_name = strip(gsub(to_n[1], pat, ""));
		}

	to_name = to_lower(to_name);

	return to_name;
	}

function generate_threshold_notice(mailfrom: string): string
	{
	local duration = duration_to_hour_mins_secs(smtp_activity[mailfrom]$end_time -
	    smtp_activity[mailfrom]$start_time);
	local n = |smtp_activity[mailfrom]$rcptto|;
	local m = |smtp_activity[mailfrom]$to|;
	local o = |smtp_activity[mailfrom]$reply_to|;
	local p = |smtp_activity[mailfrom]$subject|;

	local num = n + m;
	local msg = string_cat("Sender: ", mailfrom, " sent emails to more than: ",
	    fmt("%s [To: %s, Cc/Bcc: %s, reply_to: %s]", num, n, m, o),
	    " recipients in ", fmt("%s", duration), " uniq subjects", fmt(
	    " %s ", p));

	if ( |smtp_activity[mailfrom]$subject| < SUBJECT_THRESHOLD )
		{
		for ( s in smtp_activity[mailfrom]$subject )
			{
			##local suber = SMTPurl::decode_encoded_word(s);
			#msg += fmt (" # [%s: %s] | ", s, smtp_activity[mailfrom]$subject[s]);
			}
		}
	else
		msg += fmt("# [%s]", |smtp_activity[mailfrom]$subject|);

	return msg;
	}

function get_site_recipients_count(sender: string): count
	{
	local site_recipient = 0;
	local tset: set[string];

	for ( to in smtp_activity[sender]$to )
		{
		if ( site_email in to )
			{
			add tset[to];
			}
		}

	for ( to in smtp_activity[sender]$rcptto )
		{
		if ( site_email in to )
			add tset[to];
		}

	site_recipient = |tset|;

	return site_recipient;
	}

function process_rcptto(mailfrom: string, subject: string, rec: set[string])
	{
	for ( rcptto in rec )
		{
		rcptto = strip(gsub(rcptto, pat, ""));
		rcptto = to_lower(strip(gsub(rcptto, email_domain, "")));
		rcptto = strip(gsub(rcptto, email_domain, ""));

		if ( rcptto !in smtp_activity[mailfrom]$rcptto )
			add smtp_activity[mailfrom]$rcptto[rcptto];

		if ( rcptto !in smtp_subject_activity[subject]$recipients )
			add smtp_subject_activity[subject]$recipients[rcptto];
		}
	}

function process_to(mailfrom: string, subject: string, rec: set[string]): bool
	{
	local is_bcc = F;
	for ( to in rec )
		{
		if ( /undisclosed-recipients/ in to )
			is_bcc = T;

		local to_split = split_string(to, /,/);

		for ( every_to in to_split )
			{
			local to_n = split_string(to_split[every_to], /</);
			local to_name = ( |to_n| == 1 ) ? strip(gsub(to_n[0], pat, "")) : strip(gsub(
			    to_n[1], pat, ""));
			to_name = to_lower(to_name);
			to_name = strip(gsub(to_name, email_domain, ""));

			if ( to_name !in smtp_activity[mailfrom]$to )
				{
				add smtp_activity[mailfrom]$to[to_name];
				add smtp_subject_activity[subject]$recipients[to_name];
				}

			if ( to_name !in smtp_subject_activity[subject]$recipients )
				{
				add smtp_subject_activity[subject]$recipients[to_name];
				}
			}
		}
	return is_bcc;
	}

function process_from(mailfrom: string, subject: string, rec: string)
	{
	local fm = split_string(rec, /</);
	local from = ( |fm| == 1 ) ? strip(gsub(fm[0], pat, "")) : strip(gsub(fm[1],
	    pat, ""));

	from = to_lower(from);

	if ( rec !in smtp_activity[mailfrom]$from )
		add smtp_activity[mailfrom]$from[rec];
	}

function process_reply_to(mailfrom: string, subject: string, rec: string)
	{
	local rep_to = split_string(rec, /</);
	local reply_to: string;

	if ( |rep_to| == 1 )
		{
		reply_to = strip(gsub(rep_to[0], pat, ""));
		}
	else
		{
		reply_to = strip(gsub(rep_to[1], pat, ""));
		}

	reply_to = to_lower(strip(gsub(reply_to, email_domain, "")));


	if ( reply_to !in smtp_activity[mailfrom]$reply_to )
		add smtp_activity[mailfrom]$reply_to[reply_to];
	}

#####@if (! Cluster::is_enabled() || ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ))
### @endif

function check_smtp_thresholds(rec: SMTP::Info)
	{
	if ( ! connection_exists(rec$id) )
		return;

	local c = lookup_connection(rec$id);

	if ( ! rec?$from && ! rec?$mailfrom )
		return;

	local from = rec?$from ? rec$from : "";
	local mailfrom = rec?$mailfrom ? rec$mailfrom : clean_sender(from);

	if ( /\+caf_=/ in mailfrom )
		mailfrom = clean_sender(from);


	local clean_mf = clean_sender(mailfrom);

	if ( clean_mf in ok_bulk_sender )
		return;

	local subject = ( rec?$subject ) ? fmt("%s", rec$subject) : "";

	if ( subject == "" )
		return;

	for ( a in ok_bulk_sender )
		{
		if ( to_lower(a) == to_lower(rec$subject) )
			return;
		}

	# initialize smtp_activity[mailfrom] record
	if ( mailfrom !in smtp_activity )
		{
		local activity_rec: smtp_thresholds;
		smtp_activity[mailfrom] = activity_rec;
		smtp_activity[mailfrom]$mailfrom = fmt("%s", mailfrom);
		smtp_activity[mailfrom]$start_time = rec$ts;
		smtp_activity[mailfrom]$from = set();
		smtp_activity[mailfrom]$to = set();
		smtp_activity[mailfrom]$reply_to = set();
		smtp_activity[mailfrom]$bcc = set();
		smtp_activity[mailfrom]$urls = set();
		smtp_activity[mailfrom]$msg_origin_ip = set();
		smtp_activity[mailfrom]$attachments = set();
		smtp_activity[mailfrom]$subject = vector();
		smtp_activity[mailfrom]$msg_origin_ip = set();
		smtp_activity[mailfrom]$subject = vector();
		}

	smtp_activity[mailfrom]$end_time = rec$ts;

	smtp_activity[mailfrom]$subject[|smtp_activity[mailfrom]$subject|] = subject;
	add smtp_activity[mailfrom]$msg_origin_ip[rec$path[|rec$path| - 1]];

	if ( |smtp_activity[mailfrom]$msg_origin_ip| > 20 )
		{
		local _msg = fmt("Sender: %s recipients: %s, origin: %s", mailfrom,
		    |smtp_activity[mailfrom]$to|,
		    smtp_activity[mailfrom]$msg_origin_ip);
		NOTICE([ $note=ManyMsgOrigins, $msg=_msg, $suppress_for=6hrs, $identifier=cat(
		    mailfrom) ]);
		}

	if ( rec?$from && rec$from !in smtp_activity[mailfrom]$from )
		add smtp_activity[mailfrom]$from[rec$from];

	if ( subject !in smtp_subject_activity )
		{
		local subject_rec: smtp_subjects;
		smtp_subject_activity[subject] = subject_rec;
		smtp_subject_activity[subject]$sender = set();
		smtp_subject_activity[subject]$recipients = set();
		}

	add smtp_subject_activity[subject]$sender[mailfrom];

	local check_thresh = F;
	local check_subject_thresh = F;

	# check and process recipients

	if ( rec?$rcptto )
		process_rcptto(mailfrom, subject, rec$rcptto);

	if ( rec?$to )
		IS_BCC = process_to(mailfrom, subject, rec$to);

	if ( rec?$from )
		process_from(mailfrom, subject, rec$from);

	if ( rec?$reply_to )
		process_reply_to(mailfrom, subject, rec$reply_to);

	local site_recipient = get_site_recipients_count(mailfrom);
	local m = |smtp_subject_activity[subject]$recipients|;

	check_subject_thresh = thresh_check(smtp_subject_threshold,
	    smtp_subject_threshold_idx, subject, m);

	local msg = "";
	msg = generate_threshold_notice(mailfrom);
	msg += fmt("[LBL recipients: %s] ", site_recipient);

	if ( check_subject_thresh )
		{
		msg += fmt(":: SUBJECT: %s", subject);
		if ( site_email !in mailfrom )
			{
			NOTICE([ $note=TargetedSubject, $msg=msg ]);
			}
		else if ( site_email in mailfrom && IS_BCC )
			{
			NOTICE([ $note=bcc_HighVolumeSubject, $msg=msg ]);
			}
		else if ( site_email in mailfrom )
			{
			NOTICE([ $note=SubjectMassMail, $msg=msg ]);
			}
		}

	local n = |smtp_activity[mailfrom]$rcptto|;
	check_thresh = thresh_check(smtp_threshold, smtp_to_threshold_idx, mailfrom, n);

	if ( check_thresh )
		{
		msg = generate_threshold_notice(mailfrom);
		msg += fmt(" Number of LBL recipients: %s", site_recipient);

		local duration = smtp_activity[mailfrom]$end_time -
		    smtp_activity[mailfrom]$start_time;

		# TBD: if (|smtp_activity[mailfrom]$subject| < SUBJECT_THRESHOLD && duration < 1 hrs )

		if ( site_email in mailfrom ) # internal sender
			{
			if ( IS_BCC )
				NOTICE([ $note=InternalBCCSender, $msg=msg ]);
			else
				NOTICE([ $note=InternalMassMail, $msg=msg ]);
			}
		else
			{
			if ( IS_BCC )
				NOTICE([ $note=ExternalBCCSender, $msg=msg ]);
			else
				NOTICE([ $note=ExternalMassMail, $msg=msg ]);
			}
		}
	}

event zeek_init()
	{
	Input::add_table([ $source=ok_bulk_sender_ip_feed, $name="bulk_sender",
	    $idx=BulkSenderIdx, $val=BulkSenderVal, $destination=ok_bulk_sender,
	    $mode=Input::REREAD, $pred (typ: Input::Event, left: BulkSenderIdx,
	    right: BulkSenderVal) =
		{
		right$mailfrom = clean_sender(right$mailfrom);
		left$mailfrom = clean_sender(left$mailfrom);
		return T;
		} ]);

	#schedule 60 min { force_update_input_logs() };
	}

