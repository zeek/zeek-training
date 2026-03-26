module DNS;

export {
	global ptr_queries: table[addr] of opaque of cardinality &default=function(
	    n: any): opaque of cardinality
		{
		return hll_cardinality_init(0.001, 0.999);
		} &create_expire=1day;
}

event DNS::log_dns(rec: DNS::Info)
	{
	local request_ip: addr;
	local check_thresh: bool;

	request_ip = rec$id$orig_h;

	if ( ! rec?$qtype_name )
		print fmt("%s", rec);

	if ( rec$qtype_name != "PTR" )
		return;

	#if (! rec?$rcode)
	#print fmt ("%s %s %s %s",  rec$qtype, rec$qtype_name, rec$rcode, rec$rcode_name);
	#print fmt ("%s", rec) ;

	# for this we only care about external IPs
	# hitting our dns_servers with all sorts of queries
	#if (rec?$query && request_ip in dns_servers) {
	# return ;
	#}

	local lookup = rec$query;

	if ( request_ip !in ptr_queries )
		{
		local cp: opaque of cardinality = hll_cardinality_init(0.001, 0.999);
		ptr_queries[request_ip] = cp;
		}
	hll_cardinality_add(ptr_queries[request_ip], lookup);
	}

# [ts=1596366431.199041, uid=CY9yrx4jcEeEo2RTnk, id=[orig_h=137.74.213.136, orig_p=13938/udp, resp_h=131.243.64.3, resp_p=53/udp], proto=udp, trans_id=56404, rtt=<uninitialized>, query=181.139.146.in-addr.arpa, qclass=1, qclass_name=C_INTERNET, qtype=1, qtype_name=A, rcode=3, rcode_name=NXDOMAIN, AA=F, TC=F, RD=F, RA=F, Z=1, answers=<uninitialized>, TTLs=<uninitialized>, rejected=F, total_answers=0, total_replies=2, saw_query=T, saw_reply=T]

event zeek_done()
	{
	for ( request_ip in ptr_queries )
		{
		print fmt("ptr_queries: %s, %s", request_ip, double_to_count(
		    hll_cardinality_estimate(ptr_queries[request_ip])));
		}
	}
