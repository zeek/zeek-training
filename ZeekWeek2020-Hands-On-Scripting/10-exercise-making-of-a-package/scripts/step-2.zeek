module DNS;

#Goal: can we do this: 
#$ zeek -r Traces/ptr-dns-34.214.127.68.pcap scripts/step-1.zeek | awk '{print $4}' - | sort | uniq -c | sort -nr
#3372 NXDOMAIN
#2497 NOERROR
# 878 UNKNOWN
# 115 REFUSED

# OR 
# $ zeek -r Traces/ptr-dns-34.214.127.68.pcap scripts/step-2.zeek
# [ptr_counts=6862, noerror=2497, nxdomain=3372, refused=115, servfail=0, unknown=878]


export { 
	

# Step 1: We need a data strcuture to hold these counters 
	type ptr_stats : record {
		ptr_counts: count &default=0 ;
		noerror :   count &default=0 ;
		nxdomain:   count &default=0 ;
		refused :   count &default=0 ;
		servfail:   count &default=0 ;
		unknown :   count &default=0 ;
	} ;


# Step 2: We need a table to hold ptr_stats record 
	global ptr_queries: table[addr] of ptr_stats=table() &create_expire = 1 day ;
	
} 



	
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

	#print fmt ("%s, %s, %s, %s", request_ip, rec$query, rec$qtype_name, rcode_name); 

	
#STEP 3: check membership and initialize the table entries 

	if (request_ip ! in ptr_queries)
        {
                local cp: ptr_stats;
                ptr_queries[request_ip]=cp ;
        }

        # STEP 4: lets count ALL the ptr_queries

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


} 

# Step 5: Lets Dump the output 

event zeek_done()
{
	for (ip in ptr_queries) 
		print fmt ("%s", ptr_queries[ip]) ; 

} 

# [ts=1596366431.199041, uid=CY9yrx4jcEeEo2RTnk, id=[orig_h=137.74.213.136, orig_p=13938/udp, resp_h=131.243.64.3, resp_p=53/udp], proto=udp, trans_id=56404, rtt=<uninitialized>, query=181.139.146.in-addr.arpa, qclass=1, qclass_name=C_INTERNET, qtype=1, qtype_name=A, rcode=3, rcode_name=NXDOMAIN, AA=F, TC=F, RD=F, RA=F, Z=1, answers=<uninitialized>, TTLs=<uninitialized>, rejected=F, total_answers=0, total_replies=2, saw_query=T, saw_reply=T]



