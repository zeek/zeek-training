module trainings;

event zeek_init()
{
	local ip = 1.1.1.1; 
	local port : 22/tcp; 
	
	local sub = 1.1.1.0/24 ; 
	local answer: bool = F; 


	if (ip in subnet) 
	{ 
		answer= T; 
	} 


} 

event zeek_done()
{

	print fmt("Answer that %s is in %s: %s", ip, sub, answer); 
} 




