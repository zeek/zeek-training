module DNS;

# RCODE Response code - this 4 bit field is set as part of
#       responses.  The values have the following
#       interpretation:
#
#       0       No error condition
#
#       1       Format error - The name server was
#               unable to interpret the query.
#
#       2       Server failure - The name server was
#               unable to process this query due to a
#               problem with the name server.
#
#       3       Name Error - Meaningful only for
#               responses from an authoritative name
#               server, this code signifies that the
#               domain name referenced in the query does
#               not exist.
#
#       4       Not Implemented - The name server does
#               not support the requested kind of query.
#
#       5       Refused - The name server refuses to
#               perform the specified operation for
#               policy reasons.  For example, a name
#               server may not wish to provide the
#               information to the particular requester,
#               or a name server may not wish to perform
#               a particular operation (e.g., zone


export { 

	redef enum Notice::Type += {
                PTRThreshold,
                PTRSpike,
        };

	type ptr_stats : record { 
		ptr_counts: count &default=0 ; 
	 	noerror: count &default=0 ; 
  		nxdomain: count &default=0; 
		refused: count &default=0; 
		servfail: count &default=0 ; 
		unknown: count &default=0; 
	} ; 
		
	global ptr_queries: table[addr] of ptr_stats=table() &create_expire = 1 day ; 

	const ptr_threshold: vector of count = {
                500, 1000, 5000, 10000, 20000, 50000, 100000, 200000, 300000, 400000, 500000, 800000, 1000000,
        } &redef;
	
        global ptr_threshold_idx: table[addr] of count
                        &default=0 &write_expire = 1 day &redef;
} 

event DNS::aggregate_stats(request_ip: addr, query: string, qtype_name: string, rcode_name: string)&priority=-10 
{

	if (qtype_name != "PTR") 
		return;

        if (request_ip ! in ptr_queries)
        {
                local cp: ptr_stats;
                ptr_queries[request_ip]=cp ;

        }

	# lets count ALL the ptr_queries 	
	#hll_cardinality_add(ptr_queries[request_ip]$ptr_counts, query);

	ptr_queries[request_ip]$ptr_counts += 1; 

        switch (rcode_name)
        {
        case "NOERROR":
                ptr_queries[request_ip]$noerror += 1 ;
                break;
        case "NXDOMAIN":
                ptr_queries[request_ip]$nxdomain += 1 ;
                break;
        case "REFUSED":
                ptr_queries[request_ip]$refused += 1 ;
                break;
        case "SERVFAIL":
                ptr_queries[request_ip]$servfail+= 1 ;
                break;
        case "UNKNOWN":		 # catch all rcodes 
                ptr_queries[request_ip]$unknown+= 1 ;
                break;
        }


	local n = ptr_queries[request_ip]$ptr_counts ; 
	local check_thresh =  check_threshold(ptr_threshold, ptr_threshold_idx, request_ip, n);
	
	if (check_thresh) 
	{
       		local msg = fmt ("IP[%s] has done %s look ups: %s", request_ip, n, ptr_queries[request_ip]);
               	NOTICE([$note=DNS::PTRThreshold, $src=request_ip, $msg=msg, $identifier=cat(request_ip), $suppress_for=1 min]);
	} 
        
} 
	
# for PTR thresholds this we only care about external IPs 
# hitting our dns_servers with all sorts of queries 
event DNS::log_dns(rec: DNS::Info)
{
        local request_ip: addr;
        local check_thresh: bool;

        request_ip = rec$id$orig_h  ;


	# not interested in local_nets 
	if (Site::is_local_addr(request_ip) ) 
		return ; 

	# only interested in PTR queries  
	if (! rec?$qtype_name || rec$qtype_name  != "PTR")
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
	for (request_ip in ptr_queries) 
	{ 
		local sum = ptr_queries[request_ip]$noerror + ptr_queries[request_ip]$nxdomain + ptr_queries[request_ip]$refused + ptr_queries[request_ip]$unknown ; 

		local out=fmt ("ptr_queries: %s, %s, %s, sum: %s", request_ip,  ptr_queries[request_ip], ptr_queries[request_ip]$ptr_counts, sum); 

		log_reporter ( out, 2); 
	} 
}
