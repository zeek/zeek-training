module training; 


global services: table[addr, port] of count ; 
global distinct_peers: table[addr] of set[addr] ; 


event new_connection(c: connection)
{
	
	local orig=c$id$orig_h ;
	local resp=c$id$resp_h ;
	local service=c$id$resp_p ; 


	if ([resp, service] !in services) 
		services[resp, service] = 0 ; 
	
	services[resp, service]+= 1  ; 

	if (orig !in distinct_peers) 
		distinct_peers[orig] = set(); 

	if (resp !in distinct_peers[orig])
		add distinct_peers[orig][resp]; 

#	n = |distinct_peers[orig]|; 

} 


event zeek_done()
{

	print fmt ("uniq services seen %s", |services|); 
	print fmt ("Uniq remote IPs seen %s", |distinct_peers|); 

	for (r in services) 
		if (services[r] > 3) 
			print fmt ("%s, %s", r, services[r]); 
	

	for (rh in distinct_peers) 
			print fmt ("%s, %s", rh, |distinct_peers[rh]|); 
} 
