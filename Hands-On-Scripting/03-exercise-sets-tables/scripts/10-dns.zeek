module DNS;


# for PTR thresholds this we only care about external IPs
# hitting our dns_servers with all sorts of queries

redef Site::local_nets += { 138.183.230.0/24, } ;

export {

	#Todo: Add a table (ptr_queries) of count indexed by ip-address


}

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

#Goal 1: print -> Goal 1: request_ip: %s, query: %s, qtype_name: %s, response_code: %s"

# Goal 2:  check if request

	if (request_ip ! in ptr_queries)
	{
		ptr_queries[request_ip] = 0 ;
	}

	# increment value in ptr_queries[request_ip] by one
 	# code here
}


event zeek_done()
{
	for (ip in ptr_queries)
		print fmt ("Goal 2: %s made %s queries", ip, ptr_queries[ip]);
}
