module DNS;


# for PTR thresholds this we only care about external IPs
# hitting our dns_servers with all sorts of queries

redef Site::local_nets += { 138.183.230.0/24, } ; 

event DNS::log_dns(rec: DNS::Info)
{
	local request_ip=rec$id$orig_h ; 

	if (Site::is_local_addr(request_ip)) 
		return ; 

	print fmt ("%s", rec); 
} 
