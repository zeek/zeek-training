module SMTPurl;

export {
	## Tunables
	# How long to wait before emailing multiple message lines
	const emailbatchdelta: interval = 1mins &redef;

	# Where to send notification
	const batch_notice_email: string = "" &redef;

	# Subject line (fmt() called with this and gethostname())
	const emailsubj: string = "%s bro report" &redef;

	# Public interface
	global email: function(line: string);
}

export {
	type alert_rec: record {
		note: string;
		mail_info: string;
		http_fqdn: string;
		c: conn_id;
		uid: string;
		urls: set[string];
	};

	global expire_alerts: function(t: table[string, addr] of alert_rec, idx: any)
	    : interval;
	global alerts: table[string, addr] of alert_rec &create_expire=1mins
	    &expire_func=expire_alerts;

	global batch_notice_2: function(n: Notice::Info);
}

function batch_notice_2(n: Notice::Info)
	{
	local note: string = fmt("%s", n$note);
	local ip: addr = n$src;

	local parts = split_string(n$msg, /####/);

	local url = parts[0];
	local mail_info = parts[1];
	local http_fq = parts[2];

	if ( [ note, ip ] !in alerts )
		{
		local a: alert_rec;
		a$urls = set();
		a$mail_info = mail_info;
		a$http_fqdn = http_fq;
		a$note = fmt("%s", n$note);
		a$c = n$id;
		a$uid = n$uid;
		alerts[note, ip] = a;
		}

	if ( url !in alerts[note, ip]$urls )
		add alerts[note, ip]$urls[url];
	}

function expire_alerts(t: table[string, addr] of alert_rec, idx: any): interval
	{
	local note: string;
	local ip: addr;

	[ note, ip ] = idx;
	local temp = fmt("/tmp/email.%d,%s", getpid(), note);
	# don't map "\n" -> "^J"
	local f: file = open(temp) &raw_output;

@ifdef ( notdef )
	# XXX &raw_output doesn't work
	print f, t[ip];
@else
	print f, fmt("Connection: %s, %s", t[note, ip]$uid, t[note, ip]$c);
	print f, fmt(" ");
	print f, fmt("SMTP:: %s", t[note, ip]$mail_info);
	print f, fmt(" ");
	print f, fmt("HTTP:: %s", t[note, ip]$http_fqdn);
	print f, fmt(" ");
	print f, fmt("Clicked URLs: ");
	for ( u in t[note, ip]$urls )
		print f, fmt("%s", u);
@endif
	close(f);
	local subj = fmt("[Bro] %s ", note);
	print fmt("Firing system command with mail -s '%s' %s < %s ; rm %s", subj,
	    batch_notice_email, temp, temp);
	system(fmt("mail -s '%s' %s < %s ; rm %s", subj, batch_notice_email, temp,
	    temp));

	return 0secs;
	}

#
# Note: zeek_done() is called after persistent state is saved
#
event zeek_done()
	{
	for ( [a, i] in alerts )
		print fmt("%s", alerts[a, i]);
	}
