module trainings; 

event connection_established(c: connection)
{

	local service = c$id$resp_p; 

	if (service == 22/tcp) 
		print fmt("Found a ssh connection: c$id => %s", c$id); 
} 

