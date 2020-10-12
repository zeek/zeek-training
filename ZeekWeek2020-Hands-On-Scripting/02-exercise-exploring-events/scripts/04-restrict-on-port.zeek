module training; 

event connection_established(c: connection)
{

	local service = c$id$resp_p; 

	if (service == 22/tcp) 
		print fmt("Found a ssh connection: c$id => %s", c$id); 
} 


event zeek_init()
{
	print fmt ("") ; 
	print fmt ("================================================================================"); 
	print fmt ("Run as: zeek -r Traces/04-restrict-on-port.pcap scripts/04-restrict-on-port.zeek"); 
	print fmt ("================================================================================"); 
} 
