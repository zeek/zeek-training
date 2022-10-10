module DNS;


# for PTR thresholds this we only care about external IPs
# hitting our dns_servers with all sorts of queries

redef Site::local_nets += { 138.183.230.0/24, } ;

export {

	type ptr_stats : record {
                ptr_counts: count &default=0 ;
                noerror: count &default=0 ;
                nxdomain: count &default=0;
                refused: count &default=0;
                servfail: count &default=0 ;
                unknown: count &default=0;
        } ;

	global ptr_queries: table[addr] of ptr_stats &create_expire = 1 day ;

	global DNS::aggregate_stats: event(request_ip: addr, query: string, qtype_name: string, rcode_name: string);
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
        case "UNKNOWN":          # catch all rcodes
                ptr_queries[request_ip]$unknown+= 1 ;
                break;
        }


	print fmt ("GOAL: %s", ptr_queries[request_ip]);
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

	event DNS::aggregate_stats(request_ip, rec$query, rec$qtype_name, rcode_name);
}
