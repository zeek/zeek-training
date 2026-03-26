module DNS;

export {
	redef enum Notice::Type += { ZoneTransfer, };

	global axfr_queries: table[addr] of count &create_expire=1day;

	const axfr_threshold: vector of count = { 1, 2, 5, 10, 25, 1000, 10000, 100000,  }
	    &redef;

	global axfr_threshold_idx: table[addr] of count &default=0 &write_expire=1day
	    &redef;
}

event DNS::aggregate_stats(request_ip: addr, query: string, qtype_name: string,
    rcode_name: string) &priority=-10
	{
	if ( qtype_name != "AXFR" )
		return;

	if ( request_ip !in axfr_queries )
		{
		axfr_queries[request_ip] = 0;
		}
	axfr_queries[request_ip] += 1;

	local n = axfr_queries[request_ip];
	local check_thresh = check_threshold(axfr_threshold, axfr_threshold_idx,
	    request_ip, n);

	if ( check_thresh )
		{
		local msg = fmt("IP[%s] tried %s failed zonetransfer: %s", request_ip, n,
		    axfr_queries[request_ip]);
		NOTICE([ $note=DNS::ZoneTransfer, $src=request_ip, $n=n, $msg=msg,
		    $identifier=cat(request_ip), $suppress_for=1min ]);
		}
	}

# for Failed zone transfer attempts
event DNS::log_dns(rec: DNS::Info)
	{
	local request_ip: addr;
	local check_thresh: bool;

	request_ip = rec$id$orig_h;

	# not interested in local_nets
	if ( Site::is_local_addr(request_ip) )
		return;
	# only interested in TXT queries
	if ( ! rec?$qtype_name || rec$qtype_name != "AXFR" )
		return;

	local rcode_name = ( ! rec?$rcode_name ) ? "UNKNOWN" : rec$rcode_name;

	if ( rcode_name != "REFUSED" )
		return;

	print fmt("%s", rec);

@if ( Cluster::is_enabled() )
	Cluster::publish_hrw(Cluster::proxy_pool, request_ip, DNS::aggregate_stats,
	    request_ip, rec$query, rcode_name);
@else
	event DNS::aggregate_stats(request_ip, rec$query, rec$qtype_name, rcode_name);
@endif
	}

# [ts=1596366431.199041, uid=CY9yrx4jcEeEo2RTnk, id=[orig_h=137.74.213.136, orig_p=13938/udp, resp_h=131.243.64.3, resp_p=53/udp], proto=udp, trans_id=56404, rtt=<uninitialized>, query=181.139.146.in-addr.arpa, qclass=1, qclass_name=C_INTERNET, qtype=1, qtype_name=A, rcode=3, rcode_name=NXDOMAIN, AA=F, TC=F, RD=F, RA=F, Z=1, answers=<uninitialized>, TTLs=<uninitialized>, rejected=F, total_answers=0, total_replies=2, saw_query=T, saw_reply=T]

event zeek_done()
	{ }
