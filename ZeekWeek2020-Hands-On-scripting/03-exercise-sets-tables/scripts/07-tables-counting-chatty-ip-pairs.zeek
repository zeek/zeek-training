module training; 

#redef exit_only_after_terminate = T ; 

global expire_talkers: function( t: table[addr, addr] of count, idx: any): interval ; 

global talkers: table[addr, addr] of count &create_expire=1 hrs &expire_func=expire_talkers ; 
# experiment with read and write expire too 


event new_connection(c: connection)
{
	
	local orig=c$id$orig_h ;
	local resp=c$id$resp_h ;
	local service=c$id$resp_p ; 


	if ([orig,resp] !in talkers) 
	{ 	
		talkers[orig,resp]= 0 ; 
	} 

	talkers[orig,resp] += 1 ; 

} 


function expire_talkers(t: table[addr, addr] of count, idx: any): interval
{
	local iplist = "" ; 

	for ([r,h] in talkers) 
		{ 
			print fmt ("%s %s -> %s - %s times", network_time(), r, h, talkers[r,h]); 
		} 

	return 0 secs; 

	
} 
