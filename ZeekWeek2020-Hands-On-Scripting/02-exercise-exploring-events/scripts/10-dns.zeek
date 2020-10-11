module DNS;


# for PTR thresholds this we only care about external IPs
# hitting our dns_servers with all sorts of queries

event DNS::log_dns(rec: DNS::Info)
{

	print fmt ("%s", rec); 
} 
