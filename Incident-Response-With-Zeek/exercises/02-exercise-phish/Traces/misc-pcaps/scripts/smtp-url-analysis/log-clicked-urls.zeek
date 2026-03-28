module SMTPurl;

export {
	redef enum Log::ID += { Clicked_URLs_LOG };

	type ClickURLInfo: record {
		# When the http was seen.
		ts: time;
		# Unique ID for the connection.
		uid: string;
		# Connection details.
		id: conn_id;
		# url that was discovered.
		host: string &optional;
		url: string &optional;
		# original email which contained the URL
		mail_ts: time &optional;
		mail_uid: string &optional;
		from: string &optional;
		to: string &optional;
		subject: string &optional;
		referrer: string &optional &default="";
	} &log;

	global log_clicked_urls: function(url: string, mail_info: mi, c: connection);
}

event zeek_init() &priority=5
	{
	Log::create_stream(SMTPurl::Clicked_URLs_LOG, [ $columns=ClickURLInfo ]);
	local f = Log::get_filter(SMTPurl::Clicked_URLs_LOG, "default");
	f$path = "smtp_clicked_urls";
	Log::add_filter(SMTPurl::Clicked_URLs_LOG, f);
	}

function log_clicked_urls(url: string, mail_info: mi, c: connection)
	{
	log_reporter(fmt("EVENT: function log_clicked_urls VARS: url: %s", url), 10);

	local info: ClickURLInfo;

	info$ts = c$http$ts;
	info$uid = c$http$uid;
	info$id = c$id;
	info$url = url;
	info$host = extract_host(url);
	info$mail_ts = mail_info$ts;
	info$mail_uid = mail_info$uid;
	info$from = mail_info$from;
	info$to = mail_info$to;
	info$subject = mail_info$subject;
	info$referrer = mail_info?$referrer ? join_string_vec(mail_info$referrer,
	    " -> ") : "";

	#if (|mail_info$referrer| > 0)
	#for (r in mail_info$referrer)
	#	info$referrer += fmt(" -> %s", r);

	#print fmt ("INFO is %s", info);
	Log::write(SMTPurl::Clicked_URLs_LOG, info);
	}
