module trainings; 

event connection_established(c: connection)
{
	if (c$id$orig_h == 192.168.86.92) 
	{ 
		print fmt("Found a ssh connection: %s", c$id); 
	} 
} 

