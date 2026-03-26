module SMTPurl;

export {
	#local SMTPurl_file =  fmt( "%s/feeds/SMTPurl", @DIR);
	redef Config::config_files +=  { fmt ("%s/feeds/SMTPurl", @DIR), };

	global log_stats: event();
	global site_domain: pattern = /lbl\.gov/ &redef;
	global site_sub_domains: pattern = /lbl\.gov/ &redef;

	#global ENABLE_DATA_BACKEND=T;
	global OPTIMIZATION: bool = F &redef;

	global log_reporter: function(msg: string, debug: count);
	global SMTPurl::check_db_read_status: event();

	global START_PROCESSING = F;
	global FINISHED_READING_SMTP_FROM = F;
	global FINISHED_READING_SMTP_FROM_NAME = F;
	global FINISHED_READING_SMTP_FROM_EMAIL = F;
	global FINISHED_READING_HTTP_FQDN = F;

	global build_url_http: function(rec: HTTP::Info): string;
}

function build_url_http(rec: HTTP::Info): string
	{
	local uri = rec?$uri ? rec$uri : "/<missed_request>";

	uri = ( uri != "/" ) ? uri : "";

	local host = rec?$host ? rec$host : addr_to_uri(rec$id$resp_h);
	if ( rec$id$resp_p != 80/tcp )
		host = fmt("%s:%s", host, rec$id$resp_p);
	return fmt("http://%s%s", host, uri);
	}

function log_reporter(msg: string, debug: count)
	{
	#if (debug > 0 ) {
	#event reporter_info(network_time(), msg, peer_description);
	#}

	if ( debug > 20 )
		{
@if ( ! Cluster::is_enabled() )
		print fmt("%s", msg);
@endif
		event reporter_info(network_time(), msg, peer_description);
		}
	}

### we need a mechanism to read data from postgres tables
### before we start processing traffic otherwise
### there is a race-condition where (domain, email, name etc)
### might be seen in network before we read from the DB causing
### state issues
### we rather not process traffic than have incorrect entires in the table

event zeek_init() &priority=1
	{ #suspend_processing();
	#log_reporter(fmt("SUSPENDED PROCESSING .............."),0);
	#schedule 1 sec { SMTPurl::check_db_read_status()}  ;
	}

event SMTPurl::check_db_read_status()
	{
	# since we are not using postgress right now
	# 2023-04-06 aashish
	return;

	log_reporter(fmt("EVENT: SMTPurl::check_db_read_status"), 10);

	log_reporter(fmt("INSIDE check_db_read_status: %s, %s, %s, %s",
	    FINISHED_READING_SMTP_FROM, FINISHED_READING_SMTP_FROM_NAME,
	    FINISHED_READING_SMTP_FROM_EMAIL, FINISHED_READING_HTTP_FQDN), 0);
	if ( START_PROCESSING )
		return;

	if ( FINISHED_READING_SMTP_FROM
	    && FINISHED_READING_SMTP_FROM_NAME
	    && FINISHED_READING_SMTP_FROM_EMAIL
	    && FINISHED_READING_HTTP_FQDN )
		{
		continue_processing();
		log_reporter(fmt("CONTINUE PROCESSING .............."), 0);
		START_PROCESSING = T;
		}
	#else
	#	schedule 10 sec { SMTPurl::check_db_read_status()}  ;
	}

export {
	global uninteresting_fqdns: opaque of bloomfilter;

	# bloom filter to store expire URLs
	global mail_links_bloom: opaque of bloomfilter;

	global WRITE_LOCK = F;

	type fqdn_rec_idx: record {
		domain: string;
	};

	type fqdn_rec: record {
		domain: string;
		days_visited: vector of time;
		num_requests: count &default=0;
		last_visited: time;
		trustworthy: bool &default=F;
	} &log;

	global http_fqdn: table[string] of fqdn_rec &write_expire=10days;

	#########

	type from_rec_idx: record {
		m_from: string;
	};

	type from_rec: record {
		m_from: string;
		days_sent: vector of time;
		email: set[string];
		emails_sent: count &default=0;
		emails_recv: count &default=0;
		num_clicks: count &default=0;
		last_seen: time;
		trustworthy: bool &default=F;
	} &log;

	global smtp_from: table[string] of from_rec;

	#########

	type from_name_rec_idx: record {
		from_name: string;
	};

	type from_name_rec: record {
		from_name: string;
		days_sent: vector of time;
		email: set[string];
		emails_sent: count &default=0;
		emails_recv: count &default=0;
		num_clicks: count &default=0;
		last_seen: time;
		trustworthy: bool &default=F;
	} &log;

	global smtp_from_name: table[string] of from_name_rec;

	########

	type from_email_rec_idx: record {
		from_email: string;
	};

	type from_email_rec: record {
		from_email: string;
		days_sent: vector of time;
		name: set[string];
		emails_sent: count &default=0;
		emails_recv: count &default=0;
		num_clicks: count &default=0;
		last_seen: time;
		trustworthy: bool &default=F;
	} &log;

	global smtp_from_email: table[string] of from_email_rec;

	########

	#### recording how many emails reach name/email gets
	type recv_to_name_idx: record {
		name: string;
	};

	type recv_to_name: record {
		name: string;
		emails_recv: count &default=0;
	} &log;

	global email_recv_to_name: table[string] of recv_to_name = table();

	#######

	type recv_to_address_idx: record {
		address: string;
	};

	type recv_to_address: record {
		address: string;
		emails_recv: count &default=0;
	} &log;

	global email_recv_to_address: table[string] of recv_to_address = table();

	#########

	type smtp_rec: record {
		ts: time;
		from: string;
	};

	#############

	global extract_host: function(name: string): string;
	global find_all_urls: function(s: string): string_set;
	global find_all_urls_without_scheme: function(s: string): string_set;

	global process_smtp_urls: event(c: connection, url: string);

	########## types used in smtp-url-clicks.bro ######

	type mi: record {
		ts: time;
		uid: string &default="";
		from: string &default="";
		to: string &default="";
		subject: string &default="";
		referrer: string_vec &optional;
	};

	### function which runs the main-logic once data collection is done
	global SMTPurl::run_heuristics: function(link: string, mail_info: mi,
	    c: connection);

	### expire function for mail_links table - kicks in to handle what to do wiht expired URLs
	### 1) we log them to a database for future
	### 2) add to a bloom filter
	### 3) we use read expire so we only keep popular urls are in table and less seen go to store

	global mail_links_expire_func: function(t: table[string] of mi, link: string)
	    : interval;

	#global mail_links: table [string] of mi &create_expire=EXPIRE_INTERVAL &expire_func=mail_links_expire_func  ;
	global mail_links: table[string] of mi &read_expire=12hrs
	    &expire_func=mail_links_expire_func;

	global tmp_link_cache_expire: function(t: table[string] of connection,
	    link: string): interval;
	global tmp_link_cache: table[string] of connection &create_expire=7days
	    &expire_func=tmp_link_cache_expire;

	############### AddressBook ###########

	type addressbook_rec_idx: record {
		owner_email: string &default="";
	};

	type addressbook_rec: record {
		owner_email: string &default="";
		owner_name: string &default="";
		#entry: set[string, string] ;
		entry: set[string];
	} &log;

	global AddressBook: table[string] of addressbook_rec;

	########## base functions ##########

	global get_email_address: function(sender: string): string;
	global get_email_name: function(sender: string): string;

	#### log-smtp-urls
	global suspicious_text_in_body: pattern = /phish/ &redef;
}

function tmp_link_cache_expire(t: table[string] of connection, link: string)
    : interval
	{
	log_reporter(fmt(
	    "EVENT: function tmp_link_cache_expire: link: %s, t[link]: %s",
	    link, t[link]), 10);
	return 0secs;
	}

event zeek_init()
	{
	mail_links_bloom = bloomfilter_basic_init(0.001, 10000000);
	bloomfilter_add(mail_links_bloom, "http://testurl.com");
	uninteresting_fqdns = bloomfilter_basic_init(0.001, 10000000);
	bloomfilter_add(uninteresting_fqdns, "testurl.com");
	}

# function takes a URL as input and returns the fqdn
function extract_host(url: string): string
	{
	log_reporter(fmt("EVENT: function extract_host: %s", url), 10);

	#local parts = split_string(url, /\/|\?/);
	#return gsub(parts[2],/\.$/,"");

	local host = "";
	local domain_regex: pattern =
	    /\/\/[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}\/?/;
	local domain = find_all(url, domain_regex);

	for ( d in domain )
		{
		host = gsub(d, /\/|\.$/, "");
		#log_reporter(fmt ("DOMAIN IS : %s", host),0);
		break;
		}

	return host;
	}

# Extracts URLs discovered in arbitrary text.
function find_all_urls(s: string): string_set
	{
	return find_all(s, url_regex);
	}

# Extracts URLs discovered in arbitrary text without
# the URL scheme included.
function find_all_urls_without_scheme(s: string): string_set
	{
	local urls = find_all_urls(s);
	local return_urls: set[string] = set();
	for ( url in urls )
		{
		local no_scheme = sub(url, /^([a-zA-Z\-]{3,5})(:\/\/)/, "");
		add return_urls[no_scheme];
		}

	return return_urls;
	}

function get_email_address(sender: string): string
	{
	#log_reporter(fmt("EVENT: function get_email_address: VARS: sender: %s", sender),10);

	#email regexp: [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}
	local pat = />|<| |\"|\'|\}|\{|\(.*\)/;
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

	return escape_string(to_name);
	}

function get_email_name(sender: string): string
	{
	#log_reporter(fmt("EVENT: function get_email_name: VARS: sender: %s", sender),10);

	if ( /</ !in sender )
		return get_email_address(sender);

	local pat = /\"|\'|\{|\}/;

	local s = strip(gsub(sender, pat, ""));

	local result = strip(split_string(s, / </)[0]);

	#### if there is no name, we use email address as name
	### else a blank name causes confusion in analysis
	if ( result == "" )
		return get_email_address(sender);

	return escape_string(result);
	}
