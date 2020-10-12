module training;

local ip = 1.1.1.1; 
local sport = 22/tcp; 
local ssub = 1.1.1.0/24 ; 
local answer = F; 

event zeek_init()
{
	if (ip in ssub) 
	{ 
		answer= T; 
	} 
} 

event zeek_done()
{

	print fmt("Answer that %s is in %s: %s", ip, ssub, answer); 
} 


