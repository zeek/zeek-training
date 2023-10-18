module DNS;


# for PTR thresholds this we only care about external IPs
# hitting our dns_servers with all sorts of queries

redef Site::local_nets += { 138.183.230.0/24, } ;

export {

	 global ptr_queries: table[addr] of count &create_expire = 1 day ;

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

#Goal 1:
	print fmt ("Goal 1: request_ip: %s, query: %s, qtype_name: %s, response_code: %s", request_ip, rec$query, rec$qtype_name, rcode_name) ;

# Goal 2:

	if (request_ip ! in ptr_queries)
	{
		ptr_queries[request_ip] = 0 ;
	}
	ptr_queries[request_ip] += 1 ;

}


event zeek_done()
{
	for (ip in ptr_queries)
		print fmt ("Goal 2: %s made %s queries", ip, ptr_queries[ip]);
}
