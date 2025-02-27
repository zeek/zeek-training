module SMTPurl;

export {
	redef enum Notice::Type += { URLClick, RareURLClick, HistoricallyNewAttacker,
	    AddressSpoofer, NameSpoofer, HTTPSensitivePOST, };

	global check_smtpurl_in_http: function(rec: HTTP::Info);

	global SMTPurl::w_m_url_click: event(link: string, mail_info: mi,
	    c: connection);
	global track_post_requests: table[addr] of string &create_expire=2days &redef;

	global process_link_in_bloom: function(link: string, c: connection);
}

@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() != Cluster::MANAGER )
event zeek_init()
	{
	Broker::auto_publish(Cluster::manager_topic, SMTPurl::w_m_url_click);
	}
@endif
@endif

@if ( ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || ! Cluster::is_enabled() )

event SMTPurl::w_m_url_click(link: string, mail_info: mi, c: connection)
	{
	log_reporter(fmt(
	    "EVENT: SMTPurl::w_m_url_click: VARS: link: %s, mail_info: %s",
	    link, mail_info), 10);

	# lets populate an expired record from the database

	if ( link in mail_links )
		{
		log_reporter(fmt("EVENT:  w_m_url_click : %s, mail_info: %s", link,
		    mail_links[link]), 10);
		log_clicked_urls(link, mail_info, c);
		}
	}
@endif

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
    &priority=-3
	{
	if ( is_orig )
		{
		check_smtpurl_in_http(c$http);
		}
	}

function check_smtpurl_in_http(rec: HTTP::Info)
	{
	local is_link_clicked = F;
	local link_in_bloom = F;
	local link = SMTPurl::build_url_http(rec);

	# check against mail_links table

	if ( link in mail_links )
		is_link_clicked = T;

	local seen = bloomfilter_lookup(mail_links_bloom, link);

	if ( seen > 0 )
		link_in_bloom = T;

	# see if this HTTP URL is a 'smtp url' and of interest
	if ( ! link_in_bloom && link !in mail_links )
		return;

	# if HTTP connection info exists
	if ( ! connection_exists(rec$id) )
		{
		log_reporter(fmt("POTENTIAL PROBLEM: No connection_exists for %s", rec), 0);
		}

	local c = lookup_connection(rec$id);

	local src = rec$id$orig_h;
	local dst = rec$id$resp_h;

	# if URL is in mail_links ie active  usual process route
	# else see if we can pull mail_info for this URL from the mail_links_db

	if ( link_in_bloom )
		{
		process_link_in_bloom(link, c);
		log_reporter(fmt("check_smtpurl_in_http BLOOM LINK: %s", link), 0);
		is_link_clicked = T;
		}
	else if ( link in mail_links )
		{
		# send to manager for processing
		log_reporter(fmt("check_smtpurl_in_http ACTIVE LINK: %s", link), 0);
		event SMTPurl::w_m_url_click(link, SMTPurl::mail_links[link], c);
		is_link_clicked = T;
		}
	else
		# just a failsafe
		return;

	if ( is_link_clicked && ( dst !in track_post_requests ) )
		{
		track_post_requests[dst] = fmt("%s clicked %s to %s", src, link, dst);
		}

	if ( c$http?$referrer
	    && ( link !in mail_links )
	    && ( c$http$referrer in mail_links || link_in_bloom ) )
		{
		local track_referrer_chains = F;

		if ( track_referrer_chains )
			{
			log_reporter(fmt("New link of referrer chain: link: %s, referrer: %s for %s",
			    link, c$http$referrer, mail_links[c$http$referrer]), 2);
			SMTPurl::mail_links[link] = SMTPurl::mail_links[c$http$referrer];

			local new_link = T;

			for ( l in SMTPurl::mail_links[link]$referrer )
				if ( c$http$referrer == SMTPurl::mail_links[link]$referrer[l] )
					new_link = F;

			local referrer_counts = |SMTPurl::mail_links[link]$referrer|;

			if ( new_link && referrer_counts <= 1 )
				mail_links[link]$referrer[referrer_counts] = link;

			# if we are to track referrer chains
			# since referrer is now added to the mail_links table
			# we need to sync mail_links across the cluster

@if ( ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER ) || ( ! Cluster::is_enabled() ) )
			event SMTPurl::w_m_smtpurls_new(link, mail_links[c$http$referrer]);
@endif
			}
		}
	}

function process_link_in_bloom(link: string, c: connection)
	{
	event SMTPurl::w_m_url_click_in_bloom(link, c);
	}
