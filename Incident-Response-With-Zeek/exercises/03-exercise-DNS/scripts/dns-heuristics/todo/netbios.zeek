module DNS;


export { 

	global ptr_queries: table[addr] of opaque of cardinality
		&default = function(n: any): opaque of cardinality { return hll_cardinality_init(0.001, 0.999); }
		&create_expire = 1 day ; 
} 

event DNS::log_dns(rec: DNS::Info)
{
        local request_ip: addr;
        local check_thresh: bool;

        request_ip = rec$id$orig_h  ;


	if (!rec?$qtype_name)
		print fmt ("%s", rec) ; 

	if (rec$qtype_name  != "PTR")
                return ;

        #if (! rec?$rcode)
		#print fmt ("%s %s %s %s",  rec$qtype, rec$qtype_name, rec$rcode, rec$rcode_name);
                #print fmt ("%s", rec) ;


	# for this we only care about external IPs 
	# hitting our dns_servers with all sorts of queries 
        #if (rec?$query && request_ip in dns_servers) {
	# return ; 
	#} 
	
	local lookup=rec$query; 

	if (request_ip ! in ptr_queries) 
	{ 
		local cp: opaque of cardinality = hll_cardinality_init(0.001, 0.999); 
		ptr_queries[request_ip]=cp ; 

	} 
	hll_cardinality_add(ptr_queries[request_ip], lookup); 
} 

#event zeek_done()
#{
#	for (request_ip in ptr_queries) 
#	{ 
#		print fmt ("ptr_queries: %s, %s", request_ip,  double_to_count(hll_cardinality_estimate(ptr_queries[request_ip]))); 
#	} 
#}
