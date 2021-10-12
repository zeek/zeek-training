module training; 

event connection_established(c: connection)
{

    local orig = c$id$orig_h; 
	local service = c$id$resp_p; 

	if (service == 22/tcp) 
		print fmt("Found a ssh connection on port %s", service); 

    if (c$id$orig_h == 192.168.86.92)
       {
        print fmt (""); 
        print fmt("Found a connection from %s to %s", orig, service);
       }

} 


event zeek_init()
{
	print fmt ("") ; 
	print fmt ("================================================================================"); 
	print fmt ("Run as: zeek -r Traces/04-conditional-checks.pcap 04-conditional-checks.zeek"); 
	print fmt ("================================================================================"); 
} 
