module training; 

event connection_established(c: connection)
{
	if (c$id$orig_h == 192.168.86.92) 
	{ 
		print fmt("Found a ssh connection: %s", c$id); 
	} 
} 

event zeek_init()
{
        print fmt ("") ;
        print fmt ("================================================================================");
        print fmt ("Run as: zeek -r Traces/05-restrict-on-ip.zeek scripts/05-restrict-on-ip.zeek") ; 
        print fmt ("================================================================================");
}

