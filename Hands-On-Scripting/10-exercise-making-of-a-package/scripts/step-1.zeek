module DNS;

	
# for PTR thresholds this we only care about external IPs 
# hitting our dns_servers with all sorts of queries 

event DNS::log_dns(rec: DNS::Info)
{
        local request_ip: addr;
        request_ip = rec$id$orig_h  ;


	if (Site::is_local_addr(request_ip) ) 
		return ; 

	# only interested in PTR queries  
	if (! rec?$qtype_name || rec$qtype_name  != "PTR")
                return ;

	# some requests don't have name 
	# need to fill in why 

	local rcode_name =  (!rec?$rcode_name) ? "UNKNOWN" :  rec$rcode_name ; 

	print fmt ("%s, %s, %s, %s", request_ip, rec$query, rec$qtype_name, rcode_name); 

} 

# [ts=1596366431.199041, uid=CY9yrx4jcEeEo2RTnk, id=[orig_h=137.74.213.136, orig_p=13938/udp, resp_h=131.243.64.3, resp_p=53/udp], proto=udp, trans_id=56404, rtt=<uninitialized>, query=181.139.146.in-addr.arpa, qclass=1, qclass_name=C_INTERNET, qtype=1, qtype_name=A, rcode=3, rcode_name=NXDOMAIN, AA=F, TC=F, RD=F, RA=F, Z=1, answers=<uninitialized>, TTLs=<uninitialized>, rejected=F, total_answers=0, total_replies=2, saw_query=T, saw_reply=T]
