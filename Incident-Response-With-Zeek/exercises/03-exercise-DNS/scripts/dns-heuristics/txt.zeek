module DNS;

export {

	redef enum Notice::Type += {
                TxtThreshold,
                TxtSpike,
		VersionBind,
        };

	type txt_stats : record {
		#txt_counts: opaque of cardinality &default=hll_cardinality_init(0.1, 0.999);
		txt_counts: count &default=0 ;
		version_bind: count &default=0;
	} ;

	global txt_queries: table[addr] of txt_stats=table() &create_expire = 1 day ;


	const txt_threshold: vector of count = {
                100, 250, 500, 1000, 5000, 10000, 100000, 200000, 300000, 400000, 500000, 800000, 1000000,
        } &redef;

        global txt_threshold_idx: table[addr] of count
                        &default=0 &write_expire = 1 day &redef ;

	const query_threshold: vector of count = {
                100, 250, 500, 1000, 10000, 50000, 100000, 1000000,
        } &redef;

        global query_threshold_idx: table[addr] of count
			 &default=0 &write_expire = 1 day &redef ;

	global bad_queries: pattern = /version\.bind/ &redef ;
}

event DNS::aggregate_stats(request_ip: addr, query: string, qtype_name: string, rcode_name: string)&priority=-10
{

	if (qtype_name != "TXT")
		return ;

        if (request_ip ! in txt_queries)
        {
                local cp: txt_stats;
                txt_queries[request_ip]=cp ;

        }

	# lets count ALL the txt_queries
	#hll_cardinality_add(txt_queries[request_ip]$txt_counts, query);

	txt_queries[request_ip]$txt_counts += 1;

	if (bad_queries in query)
		txt_queries[request_ip]$version_bind += 1;



	local n = txt_queries[request_ip]$txt_counts ;
	local check_thresh = check_threshold(txt_threshold, txt_threshold_idx, request_ip, n);
	local msg ="";


	if (check_thresh)
	{
       		msg = fmt ("IP[%s] has done %s look ups: %s", request_ip, n, txt_queries[request_ip]);
               	NOTICE([$note=DNS::TxtThreshold, $src=request_ip, $n=n, $msg=msg, $identifier=cat(request_ip), $suppress_for=1 min]);
	}

	local q = txt_queries[request_ip]$version_bind ;
	check_thresh =  check_threshold(query_threshold, query_threshold_idx, request_ip, q);

	if (check_thresh)
	{
       		msg = fmt ("IP[%s] has done %s look ups: %s", request_ip, n, txt_queries[request_ip]);
               	NOTICE([$note=DNS::VersionBind, $src=request_ip, $n=q, $msg=msg, $identifier=cat(request_ip), $suppress_for=1 min]);
	}

}

# for TXT thresholds this we only care about external IPs
# hitting our dns_servers with all sorts of queries
event DNS::log_dns(rec: DNS::Info)
{
        local request_ip: addr;
        local check_thresh: bool;

        request_ip = rec$id$orig_h  ;


	# not interested in local_nets
	if (Site::is_local_addr(request_ip) )
		return ;

	# only interested in TXT queries
	if (! rec?$qtype_name || rec$qtype_name  != "TXT")
                return ;

	# some requests don't have name
	# need to fill in why

	local rcode_name =  (!rec?$rcode_name) ? "UNKNOWN" :  rec$rcode_name ;

	@if ( Cluster::is_enabled())
		Cluster::publish_hrw(Cluster::proxy_pool, request_ip, DNS::aggregate_stats, request_ip, rec$query, rec$qtype_name, rcode_name) ;
	@else
		event DNS::aggregate_stats(request_ip, rec$query, rec$qtype_name, rcode_name);
	@endif

}

# [ts=1596366431.199041, uid=CY9yrx4jcEeEo2RTnk, id=[orig_h=137.74.213.136, orig_p=13938/udp, resp_h=131.243.64.3, resp_p=53/udp], proto=udp, trans_id=56404, rtt=<uninitialized>, query=181.139.146.in-addr.arpa, qclass=1, qclass_name=C_INTERNET, qtype=1, qtype_name=A, rcode=3, rcode_name=NXDOMAIN, AA=F, TC=F, RD=F, RA=F, Z=1, answers=<uninitialized>, TTLs=<uninitialized>, rejected=F, total_answers=0, total_replies=2, saw_query=T, saw_reply=T]


event zeek_done()
{
	for (request_ip in txt_queries)
	{
		local out=fmt ("txt_queries: %s, %s, %s", request_ip,  txt_queries[request_ip], txt_queries[request_ip]$txt_counts);

		log_reporter ( out, 2);
	}
}
