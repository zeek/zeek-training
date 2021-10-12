module training;

export { 

global ip: set[addr] = {1.1.1.1, 1.1.1.2} &redef; 
global sport: set[port] = {22/tcp} ; 
global net:set[subnet] = {1.1.1.0/24} ; 
global answer: bool = F; 
} 

event zeek_init()
{

	if (sport < 1024/tcp )
		print fmt ("%s is in well-known ports", sport); 

	if (1.1.1.1 in ip) 
		print ("1.1.1.1 is in set of ips"); 


	if (ip in net) 	
		print ("ip in net"); 

} 

event zeek_done()
{

	for (i in ip) 
		print fmt("ips in ip: %s", i); 
} 


