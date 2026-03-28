#
# $Id: http-sensitive_POSTs.bro,v 1.1 2014/04/24 22:38:20 bro Exp bro $
#
# http-sensitive_POSTs.bro - Regular expression matching on POST bodies.
#
module SMTP;

export {
	redef enum Notice::Type += {
		#### Sensitive POST seen
		SensitivePOST,
		SensitivePasswd,
	};

	# Regular expression to match (unescaped) POST body
	global BadPOSTBody =
	    /[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]/ &redef;

	# Are we just concerned with inbound POSTs?
	global BadPOSTInboundOnly = F &redef;

	# Do we only want to see POSTs that returned successful HTTP status codes?
	global BadPOSTSuccessfulOnly = F &redef;

	# Maximum size of POST data to process
	global BadPOSTLength = 512 &redef;
}

global POST_entities: table[string] of string &default="";
global POST_requests: table[string] of string;

event http_request(c: connection, method: string, original_URI: string,
    unescaped_URI: string, version: string) &priority=3
	{
	#SMTPurl::log_reporter(fmt("EVENT: http_request :VARS: original_URI: %s", original_URI),20);

	# Is it a POST & one we want to look at
	if ( method == "POST"
	    && ( ! BadPOSTInboundOnly || Site::is_local_addr(c$id$resp_h) ) )
		{
		# If this a connection we're interested in, record the UID for the conn
		POST_requests[c$uid] = unescaped_URI;
		}
	}

# Delete data for a specified connection
function POST_cleanup(c: connection)
	{
	delete POST_entities[c$uid];
	delete POST_requests[c$uid];
	}

# Process the response code from the server
event http_reply(c: connection, version: string, code: count, reason: string)
	{
	#SMTPurl::log_reporter(fmt("EVENT: http_reply :VARS: c: %s", c$http ),20);

	if ( c$uid in POST_requests && BadPOSTSuccessfulOnly )
		{
		# If we didn't get an affirmative authentication code, fuggetaboutit
		if ( code < 200 || code > 299 )
			POST_cleanup(c);
		}
	}

# Process the data posted by the client
event http_entity_data(c: connection, is_orig: bool, length: count,
    data: string)
	{
	#SMTPurl::log_reporter(fmt("EVENT: http_entity_data :VARS: c: %s", c$http ),20);

	if ( is_orig && c$uid in POST_requests )
		{
		if ( |POST_entities[c$uid]| + length > BadPOSTLength )
			POST_cleanup(c);
		else
			POST_entities[c$uid] += data;
		}
	}

function password_complexity(data: string): bool
	{
	#SMTPurl::log_reporter(fmt("EVENT: password_complexity :VARS"),20);

	local dat = split_string(data, /\?/);
	for ( i in dat )
		{
		if ( BadPOSTBody in dat[i] )
			{
			local p = split_string(dat[i], /\&/);
			#print fmt("%s", p);
			local passwd = split_string(p[1], /=/);

			#if (/\!|@|#|\$|%|\^|_|-/ in passwd[1])
			#	print fmt ("YO: %s", passwd) ;

			if ( ( /[A-Z]/ in passwd[1] && /[0-9]/ in passwd[1] && /\!|@|#|\$|%|\^|_|-/ in
			    passwd[1] && |passwd[1]| > 8 )
			    || ( /testing/ in passwd[1] ) )
				{
				return T;
				}
			}
		}

	return F;
	}

# When client all done with POST, raise a notice
event http_end_entity(c: connection, is_orig: bool)
	{
	#SMTPurl::log_reporter(fmt("EVENT: http_end_entity VARS: c: %s", c$http),20);

	if ( is_orig && c$uid in POST_requests )
		{
		local uentity = unescape_URI(POST_entities[c$uid]);
		local message = fmt("Request: %s - Data: %s", POST_requests[c$uid], uentity);
		if ( |uentity| <= BadPOSTLength && BadPOSTBody in uentity )
			{
			NOTICE([ $note=SMTP::SensitivePOST, $conn=c, $msg=message ]);

			if ( SMTPurl::site_domain in uentity && password_complexity(uentity) )
				NOTICE([ $note=SMTP::SensitivePasswd, $conn=c, $msg=message ]);
			}

		if ( c$id$resp_h in SMTPurl::track_post_requests )
			{
			NOTICE([ $note=SMTP::SensitivePOST, $msg=message, $conn=c ]);
			}
		}
	POST_cleanup(c);
	}

# Cleanup of stale records as a safety net
event connection_state_remove(c: connection)
	{
	#SMTPurl::log_reporter(fmt("EVENT: connection_end VARS: c: %s", c$http),20);
	POST_cleanup(c);
	}
